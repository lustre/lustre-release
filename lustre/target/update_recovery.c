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
 * Copyright (c) 2015, 2016, Intel Corporation.
 */

/*
 * lustre/target/update_recovery.c
 *
 * This file implement the methods to handle the update recovery.
 *
 * During DNE recovery, the recovery thread will redo the operation according
 * to the transaction no, and these replay are either from client replay req
 * or update replay records(for distribute transaction) in the update log.
 * For distribute transaction replay, the replay thread will call
 * distribute_txn_replay_handle() to handle the updates.
 *
 * After the Master MDT restarts, it will retrieve the update records from all
 * of MDTs, for each distributed operation, it will check updates on all MDTs,
 * if some updates records are missing on some MDTs, the replay thread will redo
 * updates on these MDTs.
 *
 * Author: Di Wang <di.wang@intel.com>
 */
#define DEBUG_SUBSYSTEM S_CLASS

#include <lu_target.h>
#include <lustre_obdo.h>
#include <lustre_update.h>
#include <lustre_swab.h>
#include <md_object.h>
#include <obd.h>
#include <obd_class.h>

#include "tgt_internal.h"

/**
 * Lookup distribute_txn_replay req
 *
 * Lookup distribute_txn_replay in the replay list by batchid.
 * It is assumed the list has been locked before calling this function.
 *
 * \param[in] tdtd	distribute_txn_data, which holds the replay
 *                      list.
 * \param[in] batchid	batchid used by lookup.
 *
 * \retval		pointer of the replay if succeeds.
 * \retval		NULL if can not find it.
 */
static struct distribute_txn_replay_req *
dtrq_lookup(struct target_distribute_txn_data *tdtd, __u64 batchid)
{
	struct distribute_txn_replay_req	*tmp;
	struct distribute_txn_replay_req	*dtrq = NULL;

	list_for_each_entry(tmp, &tdtd->tdtd_replay_list, dtrq_list) {
		if (tmp->dtrq_batchid == batchid) {
			dtrq = tmp;
			break;
		}
	}
	return dtrq;
}

/**
 * insert distribute txn replay req
 *
 * Insert distribute txn replay to the replay list, and it assumes the
 * list has been looked. Note: the replay list is a sorted list, which
 * is sorted by master transno. It is assumed the replay list has been
 * locked before calling this function.
 *
 * \param[in] tdtd	target distribute txn data where replay list is
 * \param[in] new	distribute txn replay to be inserted
 *
 * \retval		0 if insertion succeeds
 * \retval		EEXIST if the dtrq already exists
 */
static int dtrq_insert(struct target_distribute_txn_data *tdtd,
			struct distribute_txn_replay_req *new)
{
	struct distribute_txn_replay_req *iter;

	/* Check if the dtrq has been added to the list */
	iter = dtrq_lookup(tdtd, new->dtrq_batchid);
	if (iter != NULL)
		return -EEXIST;

	list_for_each_entry_reverse(iter, &tdtd->tdtd_replay_list, dtrq_list) {
		if (iter->dtrq_master_transno > new->dtrq_master_transno)
			continue;

		/* If there are mulitple replay req with same transno, then
		 * sort them with batchid */
		if (iter->dtrq_master_transno == new->dtrq_master_transno &&
		    iter->dtrq_batchid > new->dtrq_batchid)
			continue;

		list_add(&new->dtrq_list, &iter->dtrq_list);
		break;
	}

	if (list_empty(&new->dtrq_list))
		list_add(&new->dtrq_list, &tdtd->tdtd_replay_list);

	return 0;
}

/**
 * create distribute txn replay req
 *
 * Allocate distribute txn replay req according to the update records.
 *
 * \param[in] tdtd	target distribute txn data where replay list is.
 * \param[in] record    update records from the update log.
 *
 * \retval		the pointer of distribute txn replay req if
 *                      the creation succeeds.
 * \retval		NULL if the creation fails.
 */
static struct distribute_txn_replay_req *
dtrq_create(struct target_distribute_txn_data *tdtd,
	    struct llog_update_record *lur)
{
	struct distribute_txn_replay_req *new;

	OBD_ALLOC_PTR(new);
	if (new == NULL)
		RETURN(ERR_PTR(-ENOMEM));

	new->dtrq_lur_size = llog_update_record_size(lur);
	OBD_ALLOC_LARGE(new->dtrq_lur, new->dtrq_lur_size);
	if (new->dtrq_lur == NULL) {
		OBD_FREE_PTR(new);
		RETURN(ERR_PTR(-ENOMEM));
	}

	memcpy(new->dtrq_lur, lur, new->dtrq_lur_size);

	/* If the transno in the update record is 0, it means the
	 * update are from master MDT, and it will use the master
	 * last committed transno as its master transno. Later, if
	 * the update records are gotten from slave MDTs, then these
	 * transno will be replaced.
	 * See insert_update_records_to_replay_list(). */
	if (lur->lur_update_rec.ur_master_transno == 0) {
		new->dtrq_lur->lur_update_rec.ur_master_transno =
				tdtd->tdtd_lut->lut_obd->obd_last_committed;
		new->dtrq_master_transno =
				tdtd->tdtd_lut->lut_obd->obd_last_committed;
	} else {
		new->dtrq_master_transno =
				lur->lur_update_rec.ur_master_transno;
	}

	new->dtrq_batchid = lur->lur_update_rec.ur_batchid;

	spin_lock_init(&new->dtrq_sub_list_lock);
	INIT_LIST_HEAD(&new->dtrq_sub_list);
	INIT_LIST_HEAD(&new->dtrq_list);

	RETURN(new);
}

/**
 * Lookup distribute sub replay
 *
 * Lookup distribute sub replay in the sub list of distribute_txn_replay by
 * mdt_index.
 *
 * \param[in] distribute_txn_replay_req	the distribute txn replay req to lookup
 * \param[in] mdt_index			the mdt_index as the key of lookup
 *
 * \retval		the pointer of sub replay if it can be found.
 * \retval		NULL if it can not find.
 */
struct distribute_txn_replay_req_sub *
dtrq_sub_lookup(struct distribute_txn_replay_req *dtrq, __u32 mdt_index)
{
	struct distribute_txn_replay_req_sub *dtrqs = NULL;
	struct distribute_txn_replay_req_sub *tmp;

	list_for_each_entry(tmp, &dtrq->dtrq_sub_list, dtrqs_list) {
		if (tmp->dtrqs_mdt_index == mdt_index) {
			dtrqs = tmp;
			break;
		}
	}
	return dtrqs;
}

/**
 * Try to add cookie to sub distribute txn request
 *
 * Check if the update log cookie has been added to the request, if not,
 * add it to the dtrqs_cookie_list.
 *
 * \param[in] dtrqs	sub replay req where cookies to be added.
 * \param[in] cookie	cookie to be added.
 *
 * \retval		0 if the cookie is adding succeeds.
 * \retval		negative errno if adding fails.
 */
static int dtrq_sub_add_cookie(struct distribute_txn_replay_req_sub *dtrqs,
			       struct llog_cookie *cookie)
{
	struct sub_thandle_cookie *new;

	OBD_ALLOC_PTR(new);
	if (new == NULL)
		return -ENOMEM;

	INIT_LIST_HEAD(&new->stc_list);
	new->stc_cookie = *cookie;
	/* Note: only single thread will access one sub_request each time,
	 * so no need lock here */
	list_add(&new->stc_list, &dtrqs->dtrqs_cookie_list);

	return 0;
}

/**
 * Insert distribute txn sub req replay
 *
 * Allocate sub replay req and insert distribute txn replay list.
 *
 * \param[in] dtrq	d to be added
 * \param[in] cookie	the cookie of the update record
 * \param[in] mdt_index	the mdt_index of the update record
 *
 * \retval		0 if the adding succeeds.
 * \retval		negative errno if the adding fails.
 */
static int
dtrq_sub_create_and_insert(struct distribute_txn_replay_req *dtrq,
			   struct llog_cookie *cookie,
			   __u32 mdt_index)
{
	struct distribute_txn_replay_req_sub	*dtrqs = NULL;
	struct distribute_txn_replay_req_sub	*new;
	int					rc;
	ENTRY;

	spin_lock(&dtrq->dtrq_sub_list_lock);
	dtrqs = dtrq_sub_lookup(dtrq, mdt_index);
	spin_unlock(&dtrq->dtrq_sub_list_lock);
	if (dtrqs != NULL) {
		rc = dtrq_sub_add_cookie(dtrqs, cookie);
		RETURN(0);
	}

	OBD_ALLOC_PTR(new);
	if (new == NULL)
		RETURN(-ENOMEM);

	INIT_LIST_HEAD(&new->dtrqs_list);
	INIT_LIST_HEAD(&new->dtrqs_cookie_list);
	new->dtrqs_mdt_index = mdt_index;
	spin_lock(&dtrq->dtrq_sub_list_lock);
	dtrqs = dtrq_sub_lookup(dtrq, mdt_index);
	if (dtrqs == NULL) {
		list_add(&new->dtrqs_list, &dtrq->dtrq_sub_list);
		dtrqs = new;
	} else {
		OBD_FREE_PTR(new);
	}
	spin_unlock(&dtrq->dtrq_sub_list_lock);

	rc = dtrq_sub_add_cookie(dtrqs, cookie);

	RETURN(rc);
}

/**
 * append updates to the current replay updates
 *
 * Append more updates to the existent replay update. And this is only
 * used when combining mulitple updates into one large updates during
 * replay.
 *
 * \param[in] dtrq	the update replay request where the new update
 *                      records will be added.
 * \param[in] lur	the new update record.
 *
 * \retval		0 if appending succeeds.
 * \retval		negative errno if appending fails.
 */
static int dtrq_append_updates(struct distribute_txn_replay_req *dtrq,
			       struct update_records *record)
{
	struct llog_update_record *new_lur;
	size_t lur_size = dtrq->dtrq_lur_size;
	void *ptr;
	ENTRY;

	/* Because several threads might retrieve the same records from
	 * different targets, and we only need one copy of records. So
	 * we will check if the records is in the next one, if not, just
	 * skip it */
	spin_lock(&dtrq->dtrq_sub_list_lock);
	if (dtrq->dtrq_lur->lur_update_rec.ur_index + 1 != record->ur_index) {
		spin_unlock(&dtrq->dtrq_sub_list_lock);
		RETURN(0);
	}
	dtrq->dtrq_lur->lur_update_rec.ur_index++;
	spin_unlock(&dtrq->dtrq_sub_list_lock);

	lur_size += update_records_size(record);
	OBD_ALLOC_LARGE(new_lur, lur_size);
	if (new_lur == NULL) {
		spin_lock(&dtrq->dtrq_sub_list_lock);
		dtrq->dtrq_lur->lur_update_rec.ur_index--;
		spin_unlock(&dtrq->dtrq_sub_list_lock);
		RETURN(-ENOMEM);
	}

	/* Copy the old and new records to the new allocated buffer */
	memcpy(new_lur, dtrq->dtrq_lur, dtrq->dtrq_lur_size);
	ptr = (char *)&new_lur->lur_update_rec +
		update_records_size(&new_lur->lur_update_rec);
	memcpy(ptr, &record->ur_ops,
	       update_records_size(record) -
	       offsetof(struct update_records, ur_ops));

	new_lur->lur_update_rec.ur_update_count += record->ur_update_count;
	new_lur->lur_update_rec.ur_param_count += record->ur_param_count;
	new_lur->lur_hdr.lrh_len = llog_update_record_size(new_lur);

	/* Replace the records */
	OBD_FREE_LARGE(dtrq->dtrq_lur, dtrq->dtrq_lur_size);
	dtrq->dtrq_lur = new_lur;
	dtrq->dtrq_lur_size = lur_size;
	dtrq->dtrq_lur->lur_update_rec.ur_flags = record->ur_flags;
	update_records_dump(&new_lur->lur_update_rec, D_INFO, true);
	RETURN(0);
}

/**
 * Insert update records to the replay list.
 *
 * Allocate distribute txn replay req and insert it into the replay
 * list, then insert the update records into the replay req.
 *
 * \param[in] tdtd	distribute txn replay data where the replay list
 *                      is.
 * \param[in] record    the update record
 * \param[in] cookie    cookie of the record
 * \param[in] index	mdt index of the record
 *
 * \retval		0 if the adding succeeds.
 * \retval		negative errno if the adding fails.
 */
int
insert_update_records_to_replay_list(struct target_distribute_txn_data *tdtd,
				     struct llog_update_record *lur,
				     struct llog_cookie *cookie,
				     __u32 mdt_index)
{
	struct distribute_txn_replay_req *dtrq;
	struct update_records *record = &lur->lur_update_rec;
	bool replace_record = false;
	int rc = 0;
	ENTRY;

	CDEBUG(D_HA, "%s: insert record batchid = %llu transno = %llu"
	       " mdt_index %u\n", tdtd->tdtd_lut->lut_obd->obd_name,
	       record->ur_batchid, record->ur_master_transno, mdt_index);

	/* Update batchid if necessary */
	spin_lock(&tdtd->tdtd_batchid_lock);
	if (record->ur_batchid >= tdtd->tdtd_batchid) {
		CDEBUG(D_HA, "%s update batchid from %llu" " to %llu\n",
		       tdtd->tdtd_lut->lut_obd->obd_name,
		       tdtd->tdtd_batchid, record->ur_batchid);
		tdtd->tdtd_batchid = record->ur_batchid + 1;
	}
	spin_unlock(&tdtd->tdtd_batchid_lock);

again:
	spin_lock(&tdtd->tdtd_replay_list_lock);
	/* First try to build the replay update request with the records */
	dtrq = dtrq_lookup(tdtd, record->ur_batchid);
	if (dtrq == NULL) {
		spin_unlock(&tdtd->tdtd_replay_list_lock);
		dtrq = dtrq_create(tdtd, lur);
		if (IS_ERR(dtrq))
			RETURN(PTR_ERR(dtrq));

		spin_lock(&tdtd->tdtd_replay_list_lock);
		rc = dtrq_insert(tdtd, dtrq);
		if (rc < 0) {
			spin_unlock(&tdtd->tdtd_replay_list_lock);
			dtrq_destroy(dtrq);
			if (rc == -EEXIST)
				goto again;
			return rc;
		}
	} else {
		/* If the master transno in update header is not
		* matched with the one in the record, then it means
		* the dtrq is originally created by master record,
		* so we need update master transno and reposition
		* the dtrq(by master transno) in the list and also
		* replace update record */
		if (record->ur_master_transno != 0 &&
		    dtrq->dtrq_master_transno != record->ur_master_transno &&
		    dtrq->dtrq_lur != NULL) {
			list_del_init(&dtrq->dtrq_list);
			dtrq->dtrq_lur->lur_update_rec.ur_master_transno =
						record->ur_master_transno;

			dtrq->dtrq_master_transno = record->ur_master_transno;
			replace_record = true;
			/* try to insert again */
			rc = dtrq_insert(tdtd, dtrq);
			if (rc < 0) {
				spin_unlock(&tdtd->tdtd_replay_list_lock);
				dtrq_destroy(dtrq);
				return rc;
			}
		}
	}
	spin_unlock(&tdtd->tdtd_replay_list_lock);

	/* Because there should be only thread access the update record, so
	 * we do not need lock here */
	if (replace_record) {
		/* Replace the update record and master transno */
		OBD_FREE_LARGE(dtrq->dtrq_lur, dtrq->dtrq_lur_size);
		dtrq->dtrq_lur = NULL;
		dtrq->dtrq_lur_size = llog_update_record_size(lur);
		OBD_ALLOC_LARGE(dtrq->dtrq_lur, dtrq->dtrq_lur_size);
		if (dtrq->dtrq_lur == NULL)
			return -ENOMEM;

		memcpy(dtrq->dtrq_lur, lur, dtrq->dtrq_lur_size);
	}

	/* This is a partial update records, let's try to append
	 * the record to the current replay request */
	if (record->ur_flags & UPDATE_RECORD_CONTINUE)
		rc = dtrq_append_updates(dtrq, record);

	/* Then create and add sub update request */
	rc = dtrq_sub_create_and_insert(dtrq, cookie, mdt_index);

	RETURN(rc);
}
EXPORT_SYMBOL(insert_update_records_to_replay_list);

/**
 * Dump updates of distribute txns.
 *
 * Output all of recovery updates in the distribute txn list to the
 * debug log.
 *
 * \param[in] tdtd	distribute txn data where all of distribute txn
 *                      are listed.
 * \param[in] mask	debug mask
 */
void dtrq_list_dump(struct target_distribute_txn_data *tdtd, unsigned int mask)
{
	struct distribute_txn_replay_req *dtrq;

	spin_lock(&tdtd->tdtd_replay_list_lock);
	list_for_each_entry(dtrq, &tdtd->tdtd_replay_list, dtrq_list)
		update_records_dump(&dtrq->dtrq_lur->lur_update_rec, mask,
				    false);
	spin_unlock(&tdtd->tdtd_replay_list_lock);
}
EXPORT_SYMBOL(dtrq_list_dump);

/**
 * Destroy distribute txn replay req
 *
 * Destroy distribute txn replay req and all of subs.
 *
 * \param[in] dtrq	distribute txn replqy req to be destroyed.
 */
void dtrq_destroy(struct distribute_txn_replay_req *dtrq)
{
	struct distribute_txn_replay_req_sub	*dtrqs;
	struct distribute_txn_replay_req_sub	*tmp;

	LASSERT(list_empty(&dtrq->dtrq_list));
	spin_lock(&dtrq->dtrq_sub_list_lock);
	list_for_each_entry_safe(dtrqs, tmp, &dtrq->dtrq_sub_list, dtrqs_list) {
		struct sub_thandle_cookie *stc;
		struct sub_thandle_cookie *tmp;

		list_del(&dtrqs->dtrqs_list);
		list_for_each_entry_safe(stc, tmp, &dtrqs->dtrqs_cookie_list,
					 stc_list) {
			list_del(&stc->stc_list);
			OBD_FREE_PTR(stc);
		}
		OBD_FREE_PTR(dtrqs);
	}
	spin_unlock(&dtrq->dtrq_sub_list_lock);

	if (dtrq->dtrq_lur != NULL)
		OBD_FREE_LARGE(dtrq->dtrq_lur, dtrq->dtrq_lur_size);

	OBD_FREE_PTR(dtrq);
}
EXPORT_SYMBOL(dtrq_destroy);

/**
 * Destroy all of replay req.
 *
 * Destroy all of replay req in the replay list.
 *
 * \param[in] tdtd	target distribute txn data where the replay list is.
 */
void dtrq_list_destroy(struct target_distribute_txn_data *tdtd)
{
	struct distribute_txn_replay_req *dtrq;
	struct distribute_txn_replay_req *tmp;

	spin_lock(&tdtd->tdtd_replay_list_lock);
	list_for_each_entry_safe(dtrq, tmp, &tdtd->tdtd_replay_list,
				 dtrq_list) {
		list_del_init(&dtrq->dtrq_list);
		dtrq_destroy(dtrq);
	}
	list_for_each_entry_safe(dtrq, tmp, &tdtd->tdtd_replay_finish_list,
				 dtrq_list) {
		list_del_init(&dtrq->dtrq_list);
		dtrq_destroy(dtrq);
	}
	spin_unlock(&tdtd->tdtd_replay_list_lock);
}
EXPORT_SYMBOL(dtrq_list_destroy);

/**
 * Get next req in the replay list
 *
 * Get next req needs to be replayed, since it is a sorted list
 * (by master MDT transno)
 *
 * \param[in] tdtd	distribute txn data where the replay list is
 *
 * \retval		the pointer of update recovery header
 */
struct distribute_txn_replay_req *
distribute_txn_get_next_req(struct target_distribute_txn_data *tdtd)
{
	struct distribute_txn_replay_req *dtrq = NULL;

	spin_lock(&tdtd->tdtd_replay_list_lock);
	if (!list_empty(&tdtd->tdtd_replay_list)) {
		dtrq = list_entry(tdtd->tdtd_replay_list.next,
				 struct distribute_txn_replay_req, dtrq_list);
		list_del_init(&dtrq->dtrq_list);
	}
	spin_unlock(&tdtd->tdtd_replay_list_lock);

	return dtrq;
}
EXPORT_SYMBOL(distribute_txn_get_next_req);

/**
 * Get next transno in the replay list, because this is the sorted
 * list, so it will return the transno of next req in the list.
 *
 * \param[in] tdtd	distribute txn data where the replay list is
 *
 * \retval		the transno of next update in the list
 */
__u64 distribute_txn_get_next_transno(struct target_distribute_txn_data *tdtd)
{
	struct distribute_txn_replay_req	*dtrq = NULL;
	__u64					transno = 0;

	spin_lock(&tdtd->tdtd_replay_list_lock);
	if (!list_empty(&tdtd->tdtd_replay_list)) {
		dtrq = list_entry(tdtd->tdtd_replay_list.next,
				 struct distribute_txn_replay_req, dtrq_list);
		transno = dtrq->dtrq_master_transno;
	}
	spin_unlock(&tdtd->tdtd_replay_list_lock);

	CDEBUG(D_HA, "%s: Next update transno %llu\n",
	       tdtd->tdtd_lut->lut_obd->obd_name, transno);
	return transno;
}
EXPORT_SYMBOL(distribute_txn_get_next_transno);

struct distribute_txn_replay_req *
distribute_txn_lookup_finish_list(struct target_distribute_txn_data *tdtd,
				  __u64 xid)
{
	struct distribute_txn_replay_req *dtrq = NULL;
	struct distribute_txn_replay_req *iter;

	spin_lock(&tdtd->tdtd_replay_list_lock);
	list_for_each_entry(iter, &tdtd->tdtd_replay_finish_list, dtrq_list) {
		if (iter->dtrq_xid == xid) {
			dtrq = iter;
			break;
		}
	}
	spin_unlock(&tdtd->tdtd_replay_list_lock);
	return dtrq;
}

bool is_req_replayed_by_update(struct ptlrpc_request *req)
{
	struct lu_target *tgt = class_exp2tgt(req->rq_export);
	struct distribute_txn_replay_req *dtrq;

	if (tgt->lut_tdtd == NULL)
		return false;

	dtrq = distribute_txn_lookup_finish_list(tgt->lut_tdtd, req->rq_xid);
	if (dtrq == NULL)
		return false;

	return true;
}
EXPORT_SYMBOL(is_req_replayed_by_update);

/**
 * Check if the update of one object is committed
 *
 * Check whether the update for the object is committed by checking whether
 * the correspondent sub exists in the replay req. If it is committed, mark
 * the committed flag in correspondent the sub thandle.
 *
 * \param[in] env	execution environment
 * \param[in] dtrq	replay request
 * \param[in] dt_obj	object for the update
 * \param[in] top_th	top thandle
 * \param[in] sub_th	sub thandle which the update belongs to
 *
 * \retval		1 if the update is not committed.
 * \retval		0 if the update is committed.
 * \retval		negative errno if some other failures happen.
 */
static int update_is_committed(const struct lu_env *env,
			       struct distribute_txn_replay_req *dtrq,
			       struct dt_object *dt_obj,
			       struct top_thandle *top_th,
			       struct sub_thandle *st)
{
	struct seq_server_site	*seq_site;
	const struct lu_fid	*fid = lu_object_fid(&dt_obj->do_lu);
	struct distribute_txn_replay_req_sub	*dtrqs;
	__u32			mdt_index;
	ENTRY;

	if (st->st_sub_th != NULL)
		RETURN(1);

	if (st->st_committed)
		RETURN(0);

	seq_site = lu_site2seq(dt_obj->do_lu.lo_dev->ld_site);
	if (fid_is_update_log(fid) || fid_is_update_log_dir(fid)) {
		mdt_index = fid_oid(fid);
	} else if (!fid_seq_in_fldb(fid_seq(fid))) {
		mdt_index = seq_site->ss_node_id;
	} else {
		struct lu_server_fld *fld;
		struct lu_seq_range range = {0};
		int rc;

		fld = seq_site->ss_server_fld;
		fld_range_set_type(&range, LU_SEQ_RANGE_MDT);
		LASSERT(fld->lsf_seq_lookup != NULL);
		rc = fld->lsf_seq_lookup(env, fld, fid_seq(fid),
					 &range);
		if (rc < 0)
			RETURN(rc);
		mdt_index = range.lsr_index;
	}

	dtrqs = dtrq_sub_lookup(dtrq, mdt_index);
	if (dtrqs != NULL || top_th->tt_multiple_thandle->tmt_committed) {
		st->st_committed = 1;
		if (dtrqs != NULL) {
			struct sub_thandle_cookie *stc;
			struct sub_thandle_cookie *tmp;

			list_for_each_entry_safe(stc, tmp,
						 &dtrqs->dtrqs_cookie_list,
						 stc_list)
				list_move(&stc->stc_list, &st->st_cookie_list);
		}
		RETURN(0);
	}

	CDEBUG(D_HA, "Update of "DFID "on MDT%u is not committed\n", PFID(fid),
	       mdt_index);

	RETURN(1);
}

/**
 * Implementation of different update methods for update recovery.
 *
 * These following functions update_recovery_$(update_name) implement
 * different updates recovery methods. They will extract the parameters
 * from the common parameters area and call correspondent dt API to redo
 * the update.
 *
 * \param[in] env	execution environment
 * \param[in] op	update operation to be replayed
 * \param[in] params	common update parameters which holds all parameters
 *                      of the operation
 * \param[in] th	transaction handle
 * \param[in] declare	indicate it will do declare or real execution, true
 *                      means declare, false means real execution
 *
 * \retval		0 if it succeeds.
 * \retval		negative errno if it fails.
 */
static int update_recovery_create(const struct lu_env *env,
				  struct dt_object *dt_obj,
				  const struct update_op *op,
				  const struct update_params *params,
				  struct thandle_exec_args *ta,
				  struct thandle *th)
{
	struct update_thread_info *uti = update_env_info(env);
	struct llog_update_record *lur = uti->uti_dtrq->dtrq_lur;
	struct lu_attr		*attr = &uti->uti_attr;
	struct obdo		*wobdo;
	struct obdo		*lobdo = &uti->uti_obdo;
	struct dt_object_format	dof;
	__u16			size;
	unsigned int		param_count;
	int rc;
	ENTRY;

	if (dt_object_exists(dt_obj))
		RETURN(-EEXIST);

	param_count = lur->lur_update_rec.ur_param_count;
	wobdo = update_params_get_param_buf(params, op->uop_params_off[0],
					    param_count, &size);
	if (wobdo == NULL)
		RETURN(-EIO);
	if (size != sizeof(*wobdo))
		RETURN(-EIO);

	if (LLOG_REC_HDR_NEEDS_SWABBING(&lur->lur_hdr))
		lustre_swab_obdo(wobdo);

	lustre_get_wire_obdo(NULL, lobdo, wobdo);
	la_from_obdo(attr, lobdo, lobdo->o_valid);

	dof.dof_type = dt_mode_to_dft(attr->la_mode);

	rc = out_tx_create(env, dt_obj, attr, NULL, &dof,
			   ta, th, NULL, 0);

	RETURN(rc);
}

static int update_recovery_destroy(const struct lu_env *env,
				   struct dt_object *dt_obj,
				   const struct update_op *op,
				   const struct update_params *params,
				   struct thandle_exec_args *ta,
				   struct thandle *th)
{
	int rc;
	ENTRY;

	rc = out_tx_destroy(env, dt_obj, ta, th, NULL, 0);

	RETURN(rc);
}

static int update_recovery_ref_add(const struct lu_env *env,
				   struct dt_object *dt_obj,
				   const struct update_op *op,
				   const struct update_params *params,
				   struct thandle_exec_args *ta,
				   struct thandle *th)
{
	int rc;
	ENTRY;

	rc = out_tx_ref_add(env, dt_obj, ta, th, NULL, 0);

	RETURN(rc);
}

static int update_recovery_ref_del(const struct lu_env *env,
				   struct dt_object *dt_obj,
				   const struct update_op *op,
				   const struct update_params *params,
				   struct thandle_exec_args *ta,
				   struct thandle *th)
{
	int rc;
	ENTRY;

	rc = out_tx_ref_del(env, dt_obj, ta, th, NULL, 0);

	RETURN(rc);
}

static int update_recovery_attr_set(const struct lu_env *env,
				    struct dt_object *dt_obj,
				    const struct update_op *op,
				    const struct update_params *params,
				    struct thandle_exec_args *ta,
				    struct thandle *th)
{
	struct update_thread_info *uti = update_env_info(env);
	struct llog_update_record *lur = uti->uti_dtrq->dtrq_lur;
	struct obdo	*wobdo;
	struct obdo	*lobdo = &uti->uti_obdo;
	struct lu_attr	*attr = &uti->uti_attr;
	__u16		size;
	unsigned int	param_count;
	int		rc;
	ENTRY;

	param_count = lur->lur_update_rec.ur_param_count;
	wobdo = update_params_get_param_buf(params, op->uop_params_off[0],
					    param_count, &size);
	if (wobdo == NULL)
		RETURN(-EIO);
	if (size != sizeof(*wobdo))
		RETURN(-EIO);

	if (LLOG_REC_HDR_NEEDS_SWABBING(&lur->lur_hdr))
		lustre_swab_obdo(wobdo);

	lustre_get_wire_obdo(NULL, lobdo, wobdo);
	la_from_obdo(attr, lobdo, lobdo->o_valid);

	rc = out_tx_attr_set(env, dt_obj, attr, ta, th, NULL, 0);

	RETURN(rc);
}

static int update_recovery_xattr_set(const struct lu_env *env,
				     struct dt_object *dt_obj,
				     const struct update_op *op,
				     const struct update_params *params,
				     struct thandle_exec_args *ta,
				     struct thandle *th)
{
	struct update_thread_info *uti = update_env_info(env);
	char		*buf;
	char		*name;
	int		fl;
	__u16		size;
	__u32		param_count;
	int		rc;
	ENTRY;

	param_count = uti->uti_dtrq->dtrq_lur->lur_update_rec.ur_param_count;
	name = update_params_get_param_buf(params,
					   op->uop_params_off[0],
					   param_count, &size);
	if (name == NULL)
		RETURN(-EIO);

	buf = update_params_get_param_buf(params,
					  op->uop_params_off[1],
					  param_count, &size);
	if (buf == NULL)
		RETURN(-EIO);

	uti->uti_buf.lb_buf = buf;
	uti->uti_buf.lb_len = (size_t)size;

	buf = update_params_get_param_buf(params, op->uop_params_off[2],
					  param_count, &size);
	if (buf == NULL)
		RETURN(-EIO);
	if (size != sizeof(fl))
		RETURN(-EIO);

	fl = le32_to_cpu(*(int *)buf);

	rc = out_tx_xattr_set(env, dt_obj, &uti->uti_buf, name, fl, ta, th,
			      NULL, 0);

	RETURN(rc);
}

static int update_recovery_index_insert(const struct lu_env *env,
					struct dt_object *dt_obj,
					const struct update_op *op,
					const struct update_params *params,
					struct thandle_exec_args *ta,
					struct thandle *th)
{
	struct update_thread_info *uti = update_env_info(env);
	struct lu_fid		*fid;
	char			*name;
	__u32			param_count;
	__u32			*ptype;
	__u32			type;
	__u16			size;
	int rc;
	ENTRY;

	param_count = uti->uti_dtrq->dtrq_lur->lur_update_rec.ur_param_count;
	name = update_params_get_param_buf(params, op->uop_params_off[0],
					   param_count, &size);
	if (name == NULL)
		RETURN(-EIO);

	fid = update_params_get_param_buf(params, op->uop_params_off[1],
					  param_count, &size);
	if (fid == NULL)
		RETURN(-EIO);
	if (size != sizeof(*fid))
		RETURN(-EIO);

	fid_le_to_cpu(fid, fid);

	ptype = update_params_get_param_buf(params, op->uop_params_off[2],
					    param_count, &size);
	if (ptype == NULL)
		RETURN(-EIO);
	if (size != sizeof(*ptype))
		RETURN(-EIO);
	type = le32_to_cpu(*ptype);

	if (dt_try_as_dir(env, dt_obj) == 0)
		RETURN(-ENOTDIR);

	uti->uti_rec.rec_fid = fid;
	uti->uti_rec.rec_type = type;

	rc = out_tx_index_insert(env, dt_obj,
				 (const struct dt_rec *)&uti->uti_rec,
				 (const struct dt_key *)name, ta, th,
				 NULL, 0);

	RETURN(rc);
}

static int update_recovery_index_delete(const struct lu_env *env,
					struct dt_object *dt_obj,
					const struct update_op *op,
					const struct update_params *params,
					struct thandle_exec_args *ta,
					struct thandle *th)
{
	struct update_thread_info *uti = update_env_info(env);
	__u32	param_count;
	char	*name;
	__u16	size;
	int	rc;
	ENTRY;

	param_count = uti->uti_dtrq->dtrq_lur->lur_update_rec.ur_param_count;
	name = update_params_get_param_buf(params, op->uop_params_off[0],
					   param_count, &size);
	if (name == NULL)
		RETURN(-EIO);

	if (dt_try_as_dir(env, dt_obj) == 0)
		RETURN(-ENOTDIR);

	rc = out_tx_index_delete(env, dt_obj,
				 (const struct dt_key *)name, ta, th, NULL, 0);

	RETURN(rc);
}

static int update_recovery_write(const struct lu_env *env,
				 struct dt_object *dt_obj,
				 const struct update_op *op,
				 const struct update_params *params,
				 struct thandle_exec_args *ta,
				 struct thandle *th)
{
	struct update_thread_info *uti = update_env_info(env);
	char		*buf;
	__u32		param_count;
	__u64		pos;
	__u16		size;
	int rc;
	ENTRY;

	param_count = uti->uti_dtrq->dtrq_lur->lur_update_rec.ur_param_count;
	buf = update_params_get_param_buf(params, op->uop_params_off[0],
					  param_count, &size);
	if (buf == NULL)
		RETURN(-EIO);

	uti->uti_buf.lb_buf = buf;
	uti->uti_buf.lb_len = size;

	buf = update_params_get_param_buf(params, op->uop_params_off[1],
					  param_count, &size);
	if (buf == NULL)
		RETURN(-EIO);

	pos = le64_to_cpu(*(__u64 *)buf);

	rc = out_tx_write(env, dt_obj, &uti->uti_buf, pos,
			  ta, th, NULL, 0);

	RETURN(rc);
}

static int update_recovery_xattr_del(const struct lu_env *env,
				     struct dt_object *dt_obj,
				     const struct update_op *op,
				     const struct update_params *params,
				     struct thandle_exec_args *ta,
				     struct thandle *th)
{
	struct update_thread_info *uti = update_env_info(env);
	__u32	param_count;
	char	*name;
	__u16	size;
	int	rc;
	ENTRY;

	param_count = uti->uti_dtrq->dtrq_lur->lur_update_rec.ur_param_count;
	name = update_params_get_param_buf(params, op->uop_params_off[0],
					   param_count, &size);
	if (name == NULL)
		RETURN(-EIO);

	rc = out_tx_xattr_del(env, dt_obj, name, ta, th, NULL, 0);

	RETURN(rc);
}

/**
 * Update session information
 *
 * Update session information so tgt_txn_stop_cb()->tgt_last_rcvd_update()
 * can be called correctly during update replay.
 *
 * \param[in] env	execution environment.
 * \param[in] tdtd	distribute data structure of the recovering tgt.
 * \param[in] th	thandle of this update replay.
 * \param[in] master_th	master sub thandle.
 * \param[in] ta_arg	the tx arg structure to hold the update for updating
 *                      reply data.
 */
static void update_recovery_update_ses(struct lu_env *env,
				      struct target_distribute_txn_data *tdtd,
				      struct thandle *th,
				      struct thandle *master_th,
				      struct distribute_txn_replay_req *dtrq,
				      struct tx_arg *ta_arg)
{
	struct tgt_session_info	*tsi;
	struct lu_target	*lut = tdtd->tdtd_lut;
	struct obd_export	*export;
	struct cfs_hash		*hash;
	struct top_thandle	*top_th;
	struct lsd_reply_data	*lrd;
	size_t			size;

	tsi = tgt_ses_info(env);
	if (tsi->tsi_exp != NULL)
		return;

	size = ta_arg->u.write.buf.lb_len;
	lrd = ta_arg->u.write.buf.lb_buf;
	if (size != sizeof(*lrd) || lrd == NULL)
		return;

	lrd->lrd_transno         = le64_to_cpu(lrd->lrd_transno);
	lrd->lrd_xid             = le64_to_cpu(lrd->lrd_xid);
	lrd->lrd_data            = le64_to_cpu(lrd->lrd_data);
	lrd->lrd_result          = le32_to_cpu(lrd->lrd_result);
	lrd->lrd_client_gen      = le32_to_cpu(lrd->lrd_client_gen);

	if (lrd->lrd_transno != tgt_th_info(env)->tti_transno)
		return;

	hash = cfs_hash_getref(lut->lut_obd->obd_gen_hash);
	if (hash == NULL)
		return;

	export = cfs_hash_lookup(hash, &lrd->lrd_client_gen);
	if (export == NULL) {
		cfs_hash_putref(hash);
		return;
	}

	tsi->tsi_exp = export;
	tsi->tsi_xid = lrd->lrd_xid;
	tsi->tsi_opdata = lrd->lrd_data;
	tsi->tsi_result = lrd->lrd_result;
	tsi->tsi_client_gen = lrd->lrd_client_gen;
	dtrq->dtrq_xid = lrd->lrd_xid;
	top_th = container_of(th, struct top_thandle, tt_super);
	top_th->tt_master_sub_thandle = master_th;
	cfs_hash_putref(hash);
}

/**
 * Execute updates in the update replay records
 *
 * Declare distribute txn replay by update records and add the updates
 * to the execution list. Note: it will check if the update has been
 * committed, and only execute the updates if it is not committed to
 * disk.
 *
 * \param[in] env	execution environment
 * \param[in] tdtd	distribute txn replay data which hold all of replay
 *                      reqs and all replay parameters.
 * \param[in] dtrq	distribute transaction replay req.
 * \param[in] ta	thandle execute args.
 *
 * \retval		0 if declare succeeds.
 * \retval		negative errno if declare fails.
 */
static int update_recovery_exec(const struct lu_env *env,
				struct target_distribute_txn_data *tdtd,
				struct distribute_txn_replay_req *dtrq,
				struct thandle_exec_args *ta)
{
	struct llog_update_record *lur = dtrq->dtrq_lur;
	struct update_records	*records = &lur->lur_update_rec;
	struct update_ops	*ops = &records->ur_ops;
	struct update_params	*params = update_records_get_params(records);
	struct top_thandle	*top_th = container_of(ta->ta_handle,
						       struct top_thandle,
						       tt_super);
	struct top_multiple_thandle *tmt = top_th->tt_multiple_thandle;
	struct update_op	*op;
	unsigned int		i;
	int			rc = 0;
	ENTRY;

	/* These records have been swabbed in llog_cat_process() */
	for (i = 0, op = &ops->uops_op[0]; i < records->ur_update_count;
	     i++, op = update_op_next_op(op)) {
		struct lu_fid		*fid = &op->uop_fid;
		struct dt_object	*dt_obj;
		struct dt_object	*sub_dt_obj;
		struct dt_device	*sub_dt;
		struct sub_thandle	*st;

		if (op->uop_type == OUT_NOOP)
			continue;

		dt_obj = dt_locate(env, tdtd->tdtd_dt, fid);
		if (IS_ERR(dt_obj)) {
			rc = PTR_ERR(dt_obj);
			if (rc == -EREMCHG)
				LCONSOLE_WARN("%.16s: hit invalid OI mapping "
					      "for "DFID" during recovering, "
					      "that may because auto scrub is "
					      "disabled on related MDT, and "
					      "will cause recovery failure. "
					      "Please enable auto scrub and "
					      "retry the recovery.\n",
					      tdtd->tdtd_lut->lut_obd->obd_name,
					      PFID(fid));

			break;
		}
		sub_dt_obj = dt_object_child(dt_obj);

		/* Create sub thandle if not */
		sub_dt = lu2dt_dev(sub_dt_obj->do_lu.lo_dev);
		st = lookup_sub_thandle(tmt, sub_dt);
		if (st == NULL) {
			st = create_sub_thandle(tmt, sub_dt);
			if (IS_ERR(st))
				GOTO(next, rc = PTR_ERR(st));
		}

		/* check if updates on the OSD/OSP are committed */
		rc = update_is_committed(env, dtrq, dt_obj, top_th, st);
		if (rc == 0)
			/* If this is committed, goto next */
			goto next;

		if (rc < 0)
			GOTO(next, rc);

		/* Create thandle for sub thandle if needed */
		if (st->st_sub_th == NULL) {
			rc = sub_thandle_trans_create(env, top_th, st);
			if (rc != 0)
				GOTO(next, rc);
		}

		CDEBUG(D_HA, "replay %uth update\n", i);
		switch (op->uop_type) {
		case OUT_CREATE:
			rc = update_recovery_create(env, sub_dt_obj,
						    op, params, ta,
						    st->st_sub_th);
			break;
		case OUT_DESTROY:
			rc = update_recovery_destroy(env, sub_dt_obj,
						     op, params, ta,
						     st->st_sub_th);
			break;
		case OUT_REF_ADD:
			rc = update_recovery_ref_add(env, sub_dt_obj,
						     op, params, ta,
						     st->st_sub_th);
			break;
		case OUT_REF_DEL:
			rc = update_recovery_ref_del(env, sub_dt_obj,
						     op, params, ta,
						     st->st_sub_th);
			break;
		case OUT_ATTR_SET:
			rc = update_recovery_attr_set(env, sub_dt_obj,
						      op, params, ta,
						      st->st_sub_th);
			break;
		case OUT_XATTR_SET:
			rc = update_recovery_xattr_set(env, sub_dt_obj,
						       op, params, ta,
						       st->st_sub_th);
			break;
		case OUT_INDEX_INSERT:
			rc = update_recovery_index_insert(env, sub_dt_obj,
							  op, params, ta,
							  st->st_sub_th);
			break;
		case OUT_INDEX_DELETE:
			rc = update_recovery_index_delete(env, sub_dt_obj,
							  op, params, ta,
							  st->st_sub_th);
			break;
		case OUT_WRITE:
			rc = update_recovery_write(env, sub_dt_obj,
						   op, params, ta,
						   st->st_sub_th);
			break;
		case OUT_XATTR_DEL:
			rc = update_recovery_xattr_del(env, sub_dt_obj,
						       op, params, ta,
						       st->st_sub_th);
			break;
		default:
			CERROR("Unknown update type %u\n", (__u32)op->uop_type);
			rc = -EINVAL;
			break;
		}
next:
		dt_object_put(env, dt_obj);
		if (rc < 0)
			break;
	}

	ta->ta_handle->th_result = rc;
	RETURN(rc);
}

/**
 * redo updates on MDT if needed.
 *
 * During DNE recovery, the recovery thread (target_recovery_thread) will call
 * this function to replay distribute txn updates on all MDTs. It only replay
 * updates on the MDT where the update record is missing.
 *
 * If the update already exists on the MDT, then it does not need replay the
 * updates on that MDT, and only mark the sub transaction has been committed
 * there.
 *
 * \param[in] env	execution environment
 * \param[in] tdtd	target distribute txn data, which holds the replay list
 *                      and all parameters needed by replay process.
 * \param[in] dtrq	distribute txn replay req.
 *
 * \retval		0 if replay succeeds.
 * \retval		negative errno if replay failes.
 */
int distribute_txn_replay_handle(struct lu_env *env,
				 struct target_distribute_txn_data *tdtd,
				 struct distribute_txn_replay_req *dtrq)
{
	struct update_records	*records = &dtrq->dtrq_lur->lur_update_rec;
	struct thandle_exec_args *ta;
	struct lu_context	session_env;
	struct thandle		*th = NULL;
	struct top_thandle	*top_th;
	struct top_multiple_thandle *tmt;
	struct thandle_update_records *tur = NULL;
	int			i;
	int			rc = 0;
	ENTRY;

	/* initialize session, it is needed for the handler of target */
	rc = lu_context_init(&session_env, LCT_SERVER_SESSION | LCT_NOREF);
	if (rc) {
		CERROR("%s: failure to initialize session: rc = %d\n",
		       tdtd->tdtd_lut->lut_obd->obd_name, rc);
		RETURN(rc);
	}
	lu_context_enter(&session_env);
	env->le_ses = &session_env;
	lu_env_refill(env);
	update_records_dump(records, D_HA, true);
	th = top_trans_create(env, NULL);
	if (IS_ERR(th))
		GOTO(exit_session, rc = PTR_ERR(th));

	ta = &update_env_info(env)->uti_tea;
	ta->ta_argno = 0;

	update_env_info(env)->uti_dtrq = dtrq;
	/* Create distribute transaction structure for this top thandle */
	top_th = container_of(th, struct top_thandle, tt_super);
	rc = top_trans_create_tmt(env, top_th);
	if (rc < 0)
		GOTO(stop_trans, rc);

	th->th_dev = tdtd->tdtd_dt;
	ta->ta_handle = th;

	/* check if the distribute transaction has been committed */
	tmt = top_th->tt_multiple_thandle;
	tmt->tmt_master_sub_dt = tdtd->tdtd_lut->lut_bottom;
	tmt->tmt_batchid = dtrq->dtrq_batchid;
	tgt_th_info(env)->tti_transno = dtrq->dtrq_master_transno;

	if (tmt->tmt_batchid <= tdtd->tdtd_committed_batchid)
		tmt->tmt_committed = 1;

	rc = update_recovery_exec(env, tdtd, dtrq, ta);
	if (rc < 0)
		GOTO(stop_trans, rc);

	/* If no updates are needed to be replayed, then mark this records as
	 * committed, so commit thread distribute_txn_commit_thread() will
	 * delete the record */
	if (ta->ta_argno == 0)
		tmt->tmt_committed = 1;

	tur = &update_env_info(env)->uti_tur;
	tur->tur_update_records = dtrq->dtrq_lur;
	tur->tur_update_records_buf_size = dtrq->dtrq_lur_size;
	tur->tur_update_params = NULL;
	tur->tur_update_param_count = 0;
	tmt->tmt_update_records = tur;

	distribute_txn_insert_by_batchid(tmt);
	rc = top_trans_start(env, NULL, th);
	if (rc < 0)
		GOTO(stop_trans, rc);

	for (i = 0; i < ta->ta_argno; i++) {
		struct tx_arg		*ta_arg;
		struct dt_object	*dt_obj;
		struct dt_device	*sub_dt;
		struct sub_thandle	*st;

		ta_arg = ta->ta_args[i];
		dt_obj = ta_arg->object;

		LASSERT(tmt->tmt_committed == 0);
		sub_dt = lu2dt_dev(dt_obj->do_lu.lo_dev);
		st = lookup_sub_thandle(tmt, sub_dt);

		LASSERT(st != NULL);
		LASSERT(st->st_sub_th != NULL);
		rc = ta->ta_args[i]->exec_fn(env, st->st_sub_th,
					     ta->ta_args[i]);

		/* If the update is to update the reply data, then
		 * we need set the session information, so
		 * tgt_last_rcvd_update() can be called correctly */
		if (rc == 0 && dt_obj == tdtd->tdtd_lut->lut_reply_data)
			update_recovery_update_ses(env, tdtd, th,
						   st->st_sub_th, dtrq, ta_arg);

		if (unlikely(rc < 0)) {
			CDEBUG(D_HA, "error during execution of #%u from"
			       " %s:%d: rc = %d\n", i, ta->ta_args[i]->file,
			       ta->ta_args[i]->line, rc);
			while (--i > 0) {
				if (ta->ta_args[i]->undo_fn != NULL) {
					dt_obj = ta->ta_args[i]->object;
					sub_dt =
						lu2dt_dev(dt_obj->do_lu.lo_dev);
					st = lookup_sub_thandle(tmt, sub_dt);
					LASSERT(st != NULL);
					LASSERT(st->st_sub_th != NULL);

					ta->ta_args[i]->undo_fn(env,
							       st->st_sub_th,
							       ta->ta_args[i]);
				} else {
					CERROR("%s: undo for %s:%d: rc = %d\n",
					     dt_obd_name(ta->ta_handle->th_dev),
					       ta->ta_args[i]->file,
					       ta->ta_args[i]->line, -ENOTSUPP);
				}
			}
			break;
		}
		CDEBUG(D_HA, "%s: executed %u/%u: rc = %d\n",
		       dt_obd_name(sub_dt), i, ta->ta_argno, rc);
	}

stop_trans:
	if (rc < 0)
		th->th_result = rc;
	rc = top_trans_stop(env, tdtd->tdtd_dt, th);
	for (i = 0; i < ta->ta_argno; i++) {
		if (ta->ta_args[i]->object != NULL) {
			dt_object_put(env, ta->ta_args[i]->object);
			ta->ta_args[i]->object = NULL;
		}
	}

	if (tur != NULL)
		tur->tur_update_records = NULL;

	if (tgt_ses_info(env)->tsi_exp != NULL) {
		class_export_put(tgt_ses_info(env)->tsi_exp);
		tgt_ses_info(env)->tsi_exp = NULL;
	}
exit_session:
	lu_context_exit(&session_env);
	lu_context_fini(&session_env);
	RETURN(rc);
}
EXPORT_SYMBOL(distribute_txn_replay_handle);
