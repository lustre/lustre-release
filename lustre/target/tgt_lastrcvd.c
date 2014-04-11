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
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2014, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * Lustre Unified Target
 * These are common function to work with last_received file
 *
 * Author: Mikhail Pershin <mike.pershin@intel.com>
 */
#include <obd.h>
#include <obd_class.h>
#include <lustre_fid.h>

#include "tgt_internal.h"

static inline struct lu_buf *tti_buf_lsd(struct tgt_thread_info *tti)
{
	tti->tti_buf.lb_buf = &tti->tti_lsd;
	tti->tti_buf.lb_len = sizeof(tti->tti_lsd);
	return &tti->tti_buf;
}

static inline struct lu_buf *tti_buf_lcd(struct tgt_thread_info *tti)
{
	tti->tti_buf.lb_buf = &tti->tti_lcd;
	tti->tti_buf.lb_len = sizeof(tti->tti_lcd);
	return &tti->tti_buf;
}

/**
 * Allocate in-memory data for client slot related to export.
 */
int tgt_client_alloc(struct obd_export *exp)
{
	ENTRY;
	LASSERT(exp != exp->exp_obd->obd_self_export);

	OBD_ALLOC_PTR(exp->exp_target_data.ted_lcd);
	if (exp->exp_target_data.ted_lcd == NULL)
		RETURN(-ENOMEM);
	/* Mark that slot is not yet valid, 0 doesn't work here */
	exp->exp_target_data.ted_lr_idx = -1;
	RETURN(0);
}
EXPORT_SYMBOL(tgt_client_alloc);

/**
 * Free in-memory data for client slot related to export.
 */
void tgt_client_free(struct obd_export *exp)
{
	struct tg_export_data	*ted = &exp->exp_target_data;
	struct lu_target	*lut = class_exp2tgt(exp);

	LASSERT(exp != exp->exp_obd->obd_self_export);

	OBD_FREE_PTR(ted->ted_lcd);
	ted->ted_lcd = NULL;

	/* Slot may be not yet assigned */
	if (ted->ted_lr_idx < 0)
		return;
	/* Clear bit when lcd is freed */
	LASSERT(lut && lut->lut_client_bitmap);
	if (!test_and_clear_bit(ted->ted_lr_idx, lut->lut_client_bitmap)) {
		CERROR("%s: client %u bit already clear in bitmap\n",
		       exp->exp_obd->obd_name, ted->ted_lr_idx);
		LBUG();
	}
}
EXPORT_SYMBOL(tgt_client_free);

int tgt_client_data_read(const struct lu_env *env, struct lu_target *tgt,
			 struct lsd_client_data *lcd, loff_t *off, int index)
{
	struct tgt_thread_info	*tti = tgt_th_info(env);
	int			 rc;

	tti_buf_lcd(tti);
	rc = dt_record_read(env, tgt->lut_last_rcvd, &tti->tti_buf, off);
	if (rc == 0) {
		check_lcd(tgt->lut_obd->obd_name, index, &tti->tti_lcd);
		lcd_le_to_cpu(&tti->tti_lcd, lcd);
		lcd->lcd_last_result = ptlrpc_status_ntoh(lcd->lcd_last_result);
		lcd->lcd_last_close_result =
			ptlrpc_status_ntoh(lcd->lcd_last_close_result);
	}

	CDEBUG(D_INFO, "%s: read lcd @%lld uuid = %s, last_transno = "LPU64
	       ", last_xid = "LPU64", last_result = %u, last_data = %u, "
	       "last_close_transno = "LPU64", last_close_xid = "LPU64", "
	       "last_close_result = %u, rc = %d\n", tgt->lut_obd->obd_name,
	       *off, lcd->lcd_uuid, lcd->lcd_last_transno, lcd->lcd_last_xid,
	       lcd->lcd_last_result, lcd->lcd_last_data,
	       lcd->lcd_last_close_transno, lcd->lcd_last_close_xid,
	       lcd->lcd_last_close_result, rc);
	return rc;
}

int tgt_client_data_write(const struct lu_env *env, struct lu_target *tgt,
			  struct lsd_client_data *lcd, loff_t *off,
			  struct thandle *th)
{
	struct tgt_thread_info *tti = tgt_th_info(env);

	lcd->lcd_last_result = ptlrpc_status_hton(lcd->lcd_last_result);
	lcd->lcd_last_close_result =
		ptlrpc_status_hton(lcd->lcd_last_close_result);
	lcd_cpu_to_le(lcd, &tti->tti_lcd);
	tti_buf_lcd(tti);

	return dt_record_write(env, tgt->lut_last_rcvd, &tti->tti_buf, off, th);
}

/**
 * Update client data in last_rcvd
 */
static int tgt_client_data_update(const struct lu_env *env,
				  struct obd_export *exp)
{
	struct tg_export_data	*ted = &exp->exp_target_data;
	struct lu_target	*tgt = class_exp2tgt(exp);
	struct tgt_thread_info	*tti = tgt_th_info(env);
	struct thandle		*th;
	int			 rc = 0;

	ENTRY;

	if (unlikely(tgt == NULL)) {
		CDEBUG(D_ERROR, "%s: No target for connected export\n",
			  class_exp2obd(exp)->obd_name);
		RETURN(-EINVAL);
	}

	th = dt_trans_create(env, tgt->lut_bottom);
	if (IS_ERR(th))
		RETURN(PTR_ERR(th));

	tti_buf_lcd(tti);
	rc = dt_declare_record_write(env, tgt->lut_last_rcvd,
				     &tti->tti_buf,
				     ted->ted_lr_off, th);
	if (rc)
		GOTO(out, rc);

	rc = dt_trans_start_local(env, tgt->lut_bottom, th);
	if (rc)
		GOTO(out, rc);
	/*
	 * Until this operations will be committed the sync is needed
	 * for this export. This should be done _after_ starting the
	 * transaction so that many connecting clients will not bring
	 * server down with lots of sync writes.
	 */
	rc = tgt_new_client_cb_add(th, exp);
	if (rc) {
		/* can't add callback, do sync now */
		th->th_sync = 1;
	} else {
		spin_lock(&exp->exp_lock);
		exp->exp_need_sync = 1;
		spin_unlock(&exp->exp_lock);
	}

	tti->tti_off = ted->ted_lr_off;
	rc = tgt_client_data_write(env, tgt, ted->ted_lcd, &tti->tti_off, th);
	EXIT;
out:
	dt_trans_stop(env, tgt->lut_bottom, th);
	CDEBUG(D_INFO, "%s: update last_rcvd client data for UUID = %s, "
	       "last_transno = "LPU64": rc = %d\n", tgt->lut_obd->obd_name,
	       tgt->lut_lsd.lsd_uuid, tgt->lut_lsd.lsd_last_transno, rc);

	return rc;
}

int tgt_server_data_read(const struct lu_env *env, struct lu_target *tgt)
{
	struct tgt_thread_info	*tti = tgt_th_info(env);
	int			 rc;

	tti->tti_off = 0;
	tti_buf_lsd(tti);
	rc = dt_record_read(env, tgt->lut_last_rcvd, &tti->tti_buf,
			    &tti->tti_off);
	if (rc == 0)
		lsd_le_to_cpu(&tti->tti_lsd, &tgt->lut_lsd);

	CDEBUG(D_INFO, "%s: read last_rcvd server data for UUID = %s, "
	       "last_transno = "LPU64": rc = %d\n", tgt->lut_obd->obd_name,
	       tgt->lut_lsd.lsd_uuid, tgt->lut_lsd.lsd_last_transno, rc);
        return rc;
}

int tgt_server_data_write(const struct lu_env *env, struct lu_target *tgt,
			  struct thandle *th)
{
	struct tgt_thread_info	*tti = tgt_th_info(env);
	int			 rc;

	ENTRY;

	tti->tti_off = 0;
	tti_buf_lsd(tti);
	lsd_cpu_to_le(&tgt->lut_lsd, &tti->tti_lsd);

	rc = dt_record_write(env, tgt->lut_last_rcvd, &tti->tti_buf,
			     &tti->tti_off, th);

	CDEBUG(D_INFO, "%s: write last_rcvd server data for UUID = %s, "
	       "last_transno = "LPU64": rc = %d\n", tgt->lut_obd->obd_name,
	       tgt->lut_lsd.lsd_uuid, tgt->lut_lsd.lsd_last_transno, rc);

	RETURN(rc);
}

/**
 * Update server data in last_rcvd
 */
int tgt_server_data_update(const struct lu_env *env, struct lu_target *tgt,
			   int sync)
{
	struct tgt_thread_info	*tti = tgt_th_info(env);
	struct thandle		*th;
	int			 rc = 0;

	ENTRY;

	CDEBUG(D_SUPER,
	       "%s: mount_count is "LPU64", last_transno is "LPU64"\n",
	       tgt->lut_lsd.lsd_uuid, tgt->lut_obd->u.obt.obt_mount_count,
	       tgt->lut_last_transno);

	/* Always save latest transno to keep it fresh */
	spin_lock(&tgt->lut_translock);
	tgt->lut_lsd.lsd_last_transno = tgt->lut_last_transno;
	spin_unlock(&tgt->lut_translock);

	th = dt_trans_create(env, tgt->lut_bottom);
	if (IS_ERR(th))
		RETURN(PTR_ERR(th));

	th->th_sync = sync;

	tti_buf_lsd(tti);
	rc = dt_declare_record_write(env, tgt->lut_last_rcvd,
				     &tti->tti_buf, tti->tti_off, th);
	if (rc)
		GOTO(out, rc);

	rc = dt_trans_start(env, tgt->lut_bottom, th);
	if (rc)
		GOTO(out, rc);

	rc = tgt_server_data_write(env, tgt, th);
out:
	dt_trans_stop(env, tgt->lut_bottom, th);

	CDEBUG(D_INFO, "%s: update last_rcvd server data for UUID = %s, "
	       "last_transno = "LPU64": rc = %d\n", tgt->lut_obd->obd_name,
	       tgt->lut_lsd.lsd_uuid, tgt->lut_lsd.lsd_last_transno, rc);
	RETURN(rc);
}
EXPORT_SYMBOL(tgt_server_data_update);

int tgt_truncate_last_rcvd(const struct lu_env *env, struct lu_target *tgt,
			   loff_t size)
{
	struct dt_object *dt = tgt->lut_last_rcvd;
	struct thandle	 *th;
	struct lu_attr	  attr;
	int		  rc;

	ENTRY;

	attr.la_size = size;
	attr.la_valid = LA_SIZE;

	th = dt_trans_create(env, tgt->lut_bottom);
	if (IS_ERR(th))
		RETURN(PTR_ERR(th));
	rc = dt_declare_punch(env, dt, size, OBD_OBJECT_EOF, th);
	if (rc)
		GOTO(cleanup, rc);
	rc = dt_declare_attr_set(env, dt, &attr, th);
	if (rc)
		GOTO(cleanup, rc);
	rc = dt_trans_start_local(env, tgt->lut_bottom, th);
	if (rc)
		GOTO(cleanup, rc);

	rc = dt_punch(env, dt, size, OBD_OBJECT_EOF, th);
	if (rc == 0)
		rc = dt_attr_set(env, dt, &attr, th);

cleanup:
	dt_trans_stop(env, tgt->lut_bottom, th);

	RETURN(rc);
}

static void tgt_client_epoch_update(const struct lu_env *env,
				    struct obd_export *exp)
{
	struct lsd_client_data	*lcd = exp->exp_target_data.ted_lcd;
	struct lu_target	*tgt = class_exp2tgt(exp);

	LASSERT(tgt && tgt->lut_bottom);
	/** VBR: set client last_epoch to current epoch */
	if (lcd->lcd_last_epoch >= tgt->lut_lsd.lsd_start_epoch)
		return;
	lcd->lcd_last_epoch = tgt->lut_lsd.lsd_start_epoch;
	tgt_client_data_update(env, exp);
}

/**
 * Update boot epoch when recovery ends
 */
void tgt_boot_epoch_update(struct lu_target *tgt)
{
	struct lu_env		 env;
	struct ptlrpc_request	*req;
	__u32			 start_epoch;
	struct list_head	 client_list;
	int			 rc;

	if (tgt->lut_obd->obd_stopping)
		return;

	rc = lu_env_init(&env, LCT_DT_THREAD);
	if (rc) {
		CERROR("%s: can't initialize environment: rc = %d\n",
		        tgt->lut_obd->obd_name, rc);
		return;
	}

	spin_lock(&tgt->lut_translock);
	start_epoch = lr_epoch(tgt->lut_last_transno) + 1;
	tgt->lut_last_transno = (__u64)start_epoch << LR_EPOCH_BITS;
	tgt->lut_lsd.lsd_start_epoch = start_epoch;
	spin_unlock(&tgt->lut_translock);

	INIT_LIST_HEAD(&client_list);
	/**
	 * The recovery is not yet finished and final queue can still be updated
	 * with resend requests. Move final list to separate one for processing
	 */
	spin_lock(&tgt->lut_obd->obd_recovery_task_lock);
	list_splice_init(&tgt->lut_obd->obd_final_req_queue, &client_list);
	spin_unlock(&tgt->lut_obd->obd_recovery_task_lock);

	/**
	 * go through list of exports participated in recovery and
	 * set new epoch for them
	 */
	list_for_each_entry(req, &client_list, rq_list) {
		LASSERT(!req->rq_export->exp_delayed);
		if (!req->rq_export->exp_vbr_failed)
			tgt_client_epoch_update(&env, req->rq_export);
	}
	/** return list back at once */
	spin_lock(&tgt->lut_obd->obd_recovery_task_lock);
	list_splice_init(&client_list, &tgt->lut_obd->obd_final_req_queue);
	spin_unlock(&tgt->lut_obd->obd_recovery_task_lock);
	/** update server epoch */
	tgt_server_data_update(&env, tgt, 1);
	lu_env_fini(&env);
}

/**
 * commit callback, need to update last_commited value
 */
struct tgt_last_committed_callback {
	struct dt_txn_commit_cb	 llcc_cb;
	struct lu_target	*llcc_tgt;
	struct obd_export	*llcc_exp;
	__u64			 llcc_transno;
};

static void tgt_cb_last_committed(struct lu_env *env, struct thandle *th,
				  struct dt_txn_commit_cb *cb, int err)
{
	struct tgt_last_committed_callback *ccb;

	ccb = container_of0(cb, struct tgt_last_committed_callback, llcc_cb);

	LASSERT(ccb->llcc_tgt != NULL);
	LASSERT(ccb->llcc_exp->exp_obd == ccb->llcc_tgt->lut_obd);

	spin_lock(&ccb->llcc_tgt->lut_translock);
	if (ccb->llcc_transno > ccb->llcc_tgt->lut_obd->obd_last_committed)
		ccb->llcc_tgt->lut_obd->obd_last_committed = ccb->llcc_transno;

	LASSERT(ccb->llcc_exp);
	if (ccb->llcc_transno > ccb->llcc_exp->exp_last_committed) {
		ccb->llcc_exp->exp_last_committed = ccb->llcc_transno;
		spin_unlock(&ccb->llcc_tgt->lut_translock);
		ptlrpc_commit_replies(ccb->llcc_exp);
	} else {
		spin_unlock(&ccb->llcc_tgt->lut_translock);
	}
	class_export_cb_put(ccb->llcc_exp);
	if (ccb->llcc_transno)
		CDEBUG(D_HA, "%s: transno "LPD64" is committed\n",
		       ccb->llcc_tgt->lut_obd->obd_name, ccb->llcc_transno);
	OBD_FREE_PTR(ccb);
}

int tgt_last_commit_cb_add(struct thandle *th, struct lu_target *tgt,
			   struct obd_export *exp, __u64 transno)
{
	struct tgt_last_committed_callback	*ccb;
	struct dt_txn_commit_cb			*dcb;
	int					 rc;

	OBD_ALLOC_PTR(ccb);
	if (ccb == NULL)
		return -ENOMEM;

	ccb->llcc_tgt = tgt;
	ccb->llcc_exp = class_export_cb_get(exp);
	ccb->llcc_transno = transno;

	dcb = &ccb->llcc_cb;
	dcb->dcb_func = tgt_cb_last_committed;
	INIT_LIST_HEAD(&dcb->dcb_linkage);
	strlcpy(dcb->dcb_name, "tgt_cb_last_committed", sizeof(dcb->dcb_name));

	rc = dt_trans_cb_add(th, dcb);
	if (rc) {
		class_export_cb_put(exp);
		OBD_FREE_PTR(ccb);
	}

	if (exp_connect_flags(exp) & OBD_CONNECT_LIGHTWEIGHT)
		/* report failure to force synchronous operation */
		return -EPERM;

	return rc;
}

struct tgt_new_client_callback {
	struct dt_txn_commit_cb	 lncc_cb;
	struct obd_export	*lncc_exp;
};

static void tgt_cb_new_client(struct lu_env *env, struct thandle *th,
			      struct dt_txn_commit_cb *cb, int err)
{
	struct tgt_new_client_callback *ccb;

	ccb = container_of0(cb, struct tgt_new_client_callback, lncc_cb);

	LASSERT(ccb->lncc_exp->exp_obd);

	CDEBUG(D_RPCTRACE, "%s: committing for initial connect of %s\n",
	       ccb->lncc_exp->exp_obd->obd_name,
	       ccb->lncc_exp->exp_client_uuid.uuid);

	spin_lock(&ccb->lncc_exp->exp_lock);
	/* XXX: Currently, we use per-export based sync/async policy for
	 *	the update via OUT RPC, it is coarse-grained policy, and
	 *	will be changed as per-request based by DNE II patches. */
	if (!ccb->lncc_exp->exp_keep_sync)
		ccb->lncc_exp->exp_need_sync = 0;

	spin_unlock(&ccb->lncc_exp->exp_lock);
	class_export_cb_put(ccb->lncc_exp);

	OBD_FREE_PTR(ccb);
}

int tgt_new_client_cb_add(struct thandle *th, struct obd_export *exp)
{
	struct tgt_new_client_callback	*ccb;
	struct dt_txn_commit_cb		*dcb;
	int				 rc;

	OBD_ALLOC_PTR(ccb);
	if (ccb == NULL)
		return -ENOMEM;

	ccb->lncc_exp = class_export_cb_get(exp);

	dcb = &ccb->lncc_cb;
	dcb->dcb_func = tgt_cb_new_client;
	INIT_LIST_HEAD(&dcb->dcb_linkage);
	strlcpy(dcb->dcb_name, "tgt_cb_new_client", sizeof(dcb->dcb_name));

	rc = dt_trans_cb_add(th, dcb);
	if (rc) {
		class_export_cb_put(exp);
		OBD_FREE_PTR(ccb);
	}
	return rc;
}

/**
 * Add new client to the last_rcvd upon new connection.
 *
 * We use a bitmap to locate a free space in the last_rcvd file and initialize
 * tg_export_data.
 */
int tgt_client_new(const struct lu_env *env, struct obd_export *exp)
{
	struct tg_export_data	*ted = &exp->exp_target_data;
	struct lu_target	*tgt = class_exp2tgt(exp);
	int			 rc = 0, idx;

	ENTRY;

	LASSERT(tgt && tgt->lut_client_bitmap != NULL);
	if (!strcmp(ted->ted_lcd->lcd_uuid, tgt->lut_obd->obd_uuid.uuid))
		RETURN(0);

	mutex_init(&ted->ted_lcd_lock);

	if (exp_connect_flags(exp) & OBD_CONNECT_LIGHTWEIGHT)
		RETURN(0);

	/* the bitmap operations can handle cl_idx > sizeof(long) * 8, so
	 * there's no need for extra complication here
	 */
	idx = find_first_zero_bit(tgt->lut_client_bitmap, LR_MAX_CLIENTS);
repeat:
	if (idx >= LR_MAX_CLIENTS ||
	    OBD_FAIL_CHECK(OBD_FAIL_MDS_CLIENT_ADD)) {
		CERROR("%s: no room for %u clients - fix LR_MAX_CLIENTS\n",
		       tgt->lut_obd->obd_name,  idx);
		RETURN(-EOVERFLOW);
	}
	if (test_and_set_bit(idx, tgt->lut_client_bitmap)) {
		idx = find_next_zero_bit(tgt->lut_client_bitmap,
					     LR_MAX_CLIENTS, idx);
		goto repeat;
	}

	CDEBUG(D_INFO, "%s: client at idx %d with UUID '%s' added\n",
	       tgt->lut_obd->obd_name, idx, ted->ted_lcd->lcd_uuid);

	ted->ted_lr_idx = idx;
	ted->ted_lr_off = tgt->lut_lsd.lsd_client_start +
			  idx * tgt->lut_lsd.lsd_client_size;

	LASSERTF(ted->ted_lr_off > 0, "ted_lr_off = %llu\n", ted->ted_lr_off);

	CDEBUG(D_INFO, "%s: new client at index %d (%llu) with UUID '%s'\n",
	       tgt->lut_obd->obd_name, ted->ted_lr_idx, ted->ted_lr_off,
	       ted->ted_lcd->lcd_uuid);

	if (OBD_FAIL_CHECK(OBD_FAIL_TGT_CLIENT_ADD))
		RETURN(-ENOSPC);

	rc = tgt_client_data_update(env, exp);
	if (rc)
		CERROR("%s: Failed to write client lcd at idx %d, rc %d\n",
		       tgt->lut_obd->obd_name, idx, rc);

	RETURN(rc);
}
EXPORT_SYMBOL(tgt_client_new);

/* Add client data to the MDS.  We use a bitmap to locate a free space
 * in the last_rcvd file if cl_off is -1 (i.e. a new client).
 * Otherwise, we just have to read the data from the last_rcvd file and
 * we know its offset.
 *
 * It should not be possible to fail adding an existing client - otherwise
 * mdt_init_server_data() callsite needs to be fixed.
 */
int tgt_client_add(const struct lu_env *env,  struct obd_export *exp, int idx)
{
	struct tg_export_data	*ted = &exp->exp_target_data;
	struct lu_target	*tgt = class_exp2tgt(exp);

	ENTRY;

	LASSERT(tgt && tgt->lut_client_bitmap != NULL);
	LASSERTF(idx >= 0, "%d\n", idx);

	if (!strcmp(ted->ted_lcd->lcd_uuid, tgt->lut_obd->obd_uuid.uuid) ||
	    exp_connect_flags(exp) & OBD_CONNECT_LIGHTWEIGHT)
		RETURN(0);

	if (test_and_set_bit(idx, tgt->lut_client_bitmap)) {
		CERROR("%s: client %d: bit already set in bitmap!!\n",
		       tgt->lut_obd->obd_name,  idx);
		LBUG();
	}

	CDEBUG(D_INFO, "%s: client at idx %d with UUID '%s' added\n",
	       tgt->lut_obd->obd_name, idx, ted->ted_lcd->lcd_uuid);

	ted->ted_lr_idx = idx;
	ted->ted_lr_off = tgt->lut_lsd.lsd_client_start +
			  idx * tgt->lut_lsd.lsd_client_size;

	mutex_init(&ted->ted_lcd_lock);

	LASSERTF(ted->ted_lr_off > 0, "ted_lr_off = %llu\n", ted->ted_lr_off);

	RETURN(0);
}

int tgt_client_del(const struct lu_env *env, struct obd_export *exp)
{
	struct tg_export_data	*ted = &exp->exp_target_data;
	struct lu_target	*tgt = class_exp2tgt(exp);
	int			 rc;

	ENTRY;

	LASSERT(ted->ted_lcd);

	if (unlikely(tgt == NULL)) {
		CDEBUG(D_ERROR, "%s: No target for connected export\n",
		       class_exp2obd(exp)->obd_name);
		RETURN(-EINVAL);
	}

	/* XXX if lcd_uuid were a real obd_uuid, I could use obd_uuid_equals */
	if (!strcmp((char *)ted->ted_lcd->lcd_uuid,
		    (char *)tgt->lut_obd->obd_uuid.uuid) ||
	    exp_connect_flags(exp) & OBD_CONNECT_LIGHTWEIGHT)
		RETURN(0);

	CDEBUG(D_INFO, "%s: del client at idx %u, off %lld, UUID '%s'\n",
	       tgt->lut_obd->obd_name, ted->ted_lr_idx, ted->ted_lr_off,
	       ted->ted_lcd->lcd_uuid);

	/* Clear the bit _after_ zeroing out the client so we don't
	   race with filter_client_add and zero out new clients.*/
	if (!test_bit(ted->ted_lr_idx, tgt->lut_client_bitmap)) {
		CERROR("%s: client %u: bit already clear in bitmap!!\n",
		       tgt->lut_obd->obd_name, ted->ted_lr_idx);
		LBUG();
	}

	/* Do not erase record for recoverable client. */
	if (exp->exp_flags & OBD_OPT_FAILOVER)
		RETURN(0);

	/* Make sure the server's last_transno is up to date.
	 * This should be done before zeroing client slot so last_transno will
	 * be in server data or in client data in case of failure */
	rc = tgt_server_data_update(env, tgt, 0);
	if (rc != 0) {
		CERROR("%s: failed to update server data, skip client %s "
		       "zeroing, rc %d\n", tgt->lut_obd->obd_name,
		       ted->ted_lcd->lcd_uuid, rc);
		RETURN(rc);
	}

	mutex_lock(&ted->ted_lcd_lock);
	memset(ted->ted_lcd->lcd_uuid, 0, sizeof ted->ted_lcd->lcd_uuid);
	rc = tgt_client_data_update(env, exp);
	mutex_unlock(&ted->ted_lcd_lock);

	CDEBUG(rc == 0 ? D_INFO : D_ERROR,
	       "%s: zeroing out client %s at idx %u (%llu), rc %d\n",
	       tgt->lut_obd->obd_name, ted->ted_lcd->lcd_uuid,
	       ted->ted_lr_idx, ted->ted_lr_off, rc);
	RETURN(rc);
}
EXPORT_SYMBOL(tgt_client_del);

/*
 * last_rcvd & last_committed update callbacks
 */
static int tgt_last_rcvd_update(const struct lu_env *env, struct lu_target *tgt,
				struct dt_object *obj, __u64 opdata,
				struct thandle *th, struct ptlrpc_request *req)
{
	struct tgt_thread_info	*tti = tgt_th_info(env);
	struct tg_export_data	*ted;
	__u64			*transno_p;
	int			 rc = 0;
	bool			 lw_client, update = false;

	ENTRY;

	ted = &req->rq_export->exp_target_data;

	lw_client = exp_connect_flags(req->rq_export) & OBD_CONNECT_LIGHTWEIGHT;
	if (ted->ted_lr_idx < 0 && !lw_client)
		/* ofd connect may cause transaction before export has
		 * last_rcvd slot */
		RETURN(0);

	tti->tti_transno = lustre_msg_get_transno(req->rq_reqmsg);

	spin_lock(&tgt->lut_translock);
	if (th->th_result != 0) {
		if (tti->tti_transno != 0) {
			CERROR("%s: replay transno "LPU64" failed: rc = %d\n",
			       tgt_name(tgt), tti->tti_transno, th->th_result);
		}
	} else if (tti->tti_transno == 0) {
		tti->tti_transno = ++tgt->lut_last_transno;
	} else {
		/* should be replay */
		if (tti->tti_transno > tgt->lut_last_transno)
			tgt->lut_last_transno = tti->tti_transno;
	}
	spin_unlock(&tgt->lut_translock);

	/** VBR: set new versions */
	if (th->th_result == 0 && obj != NULL)
		dt_version_set(env, obj, tti->tti_transno, th);

	/* filling reply data */
	CDEBUG(D_INODE, "transno = "LPU64", last_committed = "LPU64"\n",
	       tti->tti_transno, tgt->lut_obd->obd_last_committed);

	req->rq_transno = tti->tti_transno;
	lustre_msg_set_transno(req->rq_repmsg, tti->tti_transno);

	/* if can't add callback, do sync write */
	th->th_sync |= !!tgt_last_commit_cb_add(th, tgt, req->rq_export,
						tti->tti_transno);

	if (lw_client) {
		/* All operations performed by LW clients are synchronous and
		 * we store the committed transno in the last_rcvd header */
		spin_lock(&tgt->lut_translock);
		if (tti->tti_transno > tgt->lut_lsd.lsd_last_transno) {
			tgt->lut_lsd.lsd_last_transno = tti->tti_transno;
			update = true;
		}
		spin_unlock(&tgt->lut_translock);
		/* Although lightweight (LW) connections have no slot in
		 * last_rcvd, we still want to maintain the in-memory
		 * lsd_client_data structure in order to properly handle reply
		 * reconstruction. */
	} else if (ted->ted_lr_off == 0) {
		CERROR("%s: client idx %d has offset %lld\n",
		       tgt_name(tgt), ted->ted_lr_idx, ted->ted_lr_off);
		RETURN(-EINVAL);
	}

	/* if the export has already been disconnected, we have no last_rcvd
	 * slot, update server data with latest transno then */
	if (ted->ted_lcd == NULL) {
		CWARN("commit transaction for disconnected client %s: rc %d\n",
		      req->rq_export->exp_client_uuid.uuid, rc);
		GOTO(srv_update, rc = 0);
	}

	mutex_lock(&ted->ted_lcd_lock);
	LASSERT(ergo(tti->tti_transno == 0, th->th_result != 0));
	if (lustre_msg_get_opc(req->rq_reqmsg) == MDS_CLOSE) {
		transno_p = &ted->ted_lcd->lcd_last_close_transno;
		ted->ted_lcd->lcd_last_close_xid = req->rq_xid;
		ted->ted_lcd->lcd_last_close_result = th->th_result;
	} else {
		/* VBR: save versions in last_rcvd for reconstruct. */
		__u64 *pre_versions = lustre_msg_get_versions(req->rq_repmsg);

		if (pre_versions) {
			ted->ted_lcd->lcd_pre_versions[0] = pre_versions[0];
			ted->ted_lcd->lcd_pre_versions[1] = pre_versions[1];
			ted->ted_lcd->lcd_pre_versions[2] = pre_versions[2];
			ted->ted_lcd->lcd_pre_versions[3] = pre_versions[3];
		}
		transno_p = &ted->ted_lcd->lcd_last_transno;
		ted->ted_lcd->lcd_last_xid = req->rq_xid;
		ted->ted_lcd->lcd_last_result = th->th_result;
		/* XXX: lcd_last_data is __u32 but intent_dispostion is __u64,
		 * see struct ldlm_reply->lock_policy_res1; */
		ted->ted_lcd->lcd_last_data = opdata;
	}

	/* Update transno in slot only if non-zero number, i.e. no errors */
	if (likely(tti->tti_transno != 0)) {
		if (*transno_p > tti->tti_transno &&
		    !tgt->lut_no_reconstruct) {
			CERROR("%s: trying to overwrite bigger transno:"
			       "on-disk: "LPU64", new: "LPU64" replay: %d. "
			       "see LU-617.\n", tgt_name(tgt), *transno_p,
			       tti->tti_transno, req_is_replay(req));
			if (req_is_replay(req)) {
				spin_lock(&req->rq_export->exp_lock);
				req->rq_export->exp_vbr_failed = 1;
				spin_unlock(&req->rq_export->exp_lock);
			}
			mutex_unlock(&ted->ted_lcd_lock);
			RETURN(req_is_replay(req) ? -EOVERFLOW : 0);
		}
		*transno_p = tti->tti_transno;
	}

	if (!lw_client) {
		tti->tti_off = ted->ted_lr_off;
		rc = tgt_client_data_write(env, tgt, ted->ted_lcd, &tti->tti_off, th);
		if (rc < 0) {
			mutex_unlock(&ted->ted_lcd_lock);
			RETURN(rc);
		}
	}
	mutex_unlock(&ted->ted_lcd_lock);
	EXIT;
srv_update:
	if (update)
		rc = tgt_server_data_write(env, tgt, th);
	return rc;
}

/*
 * last_rcvd update for echo client simulation.
 * It updates last_rcvd client slot and version of object in
 * simple way but with all locks to simulate all drawbacks
 */
static int tgt_last_rcvd_update_echo(const struct lu_env *env,
				     struct lu_target *tgt,
				     struct dt_object *obj,
				     struct thandle *th,
				     struct obd_export *exp)
{
	struct tgt_thread_info	*tti = tgt_th_info(env);
	struct tg_export_data	*ted = &exp->exp_target_data;
	int			 rc = 0;

	ENTRY;

	tti->tti_transno = 0;

	spin_lock(&tgt->lut_translock);
	if (th->th_result == 0)
		tti->tti_transno = ++tgt->lut_last_transno;
	spin_unlock(&tgt->lut_translock);

	/** VBR: set new versions */
	if (th->th_result == 0 && obj != NULL)
		dt_version_set(env, obj, tti->tti_transno, th);

	/* if can't add callback, do sync write */
	th->th_sync |= !!tgt_last_commit_cb_add(th, tgt, exp,
						tti->tti_transno);

	LASSERT(ted->ted_lr_off > 0);

	mutex_lock(&ted->ted_lcd_lock);
	LASSERT(ergo(tti->tti_transno == 0, th->th_result != 0));
	ted->ted_lcd->lcd_last_transno = tti->tti_transno;
	ted->ted_lcd->lcd_last_result = th->th_result;

	tti->tti_off = ted->ted_lr_off;
	rc = tgt_client_data_write(env, tgt, ted->ted_lcd, &tti->tti_off, th);
	mutex_unlock(&ted->ted_lcd_lock);
	RETURN(rc);
}

static int tgt_clients_data_init(const struct lu_env *env,
				 struct lu_target *tgt,
				 unsigned long last_size)
{
	struct obd_device	*obd = tgt->lut_obd;
	struct lr_server_data	*lsd = &tgt->lut_lsd;
	struct lsd_client_data	*lcd = NULL;
	struct tg_export_data	*ted;
	int			 cl_idx;
	int			 rc = 0;
	loff_t			 off = lsd->lsd_client_start;

	ENTRY;

	CLASSERT(offsetof(struct lsd_client_data, lcd_padding) +
		 sizeof(lcd->lcd_padding) == LR_CLIENT_SIZE);

	OBD_ALLOC_PTR(lcd);
	if (lcd == NULL)
		RETURN(-ENOMEM);

	for (cl_idx = 0; off < last_size; cl_idx++) {
		struct obd_export	*exp;
		__u64			 last_transno;

		/* Don't assume off is incremented properly by
		 * read_record(), in case sizeof(*lcd)
		 * isn't the same as fsd->lsd_client_size.  */
		off = lsd->lsd_client_start + cl_idx * lsd->lsd_client_size;
		rc = tgt_client_data_read(env, tgt, lcd, &off, cl_idx);
		if (rc) {
			CERROR("%s: error reading last_rcvd %s idx %d off "
			       "%llu: rc = %d\n", tgt_name(tgt), LAST_RCVD,
			       cl_idx, off, rc);
			rc = 0;
			break; /* read error shouldn't cause startup to fail */
		}

		if (lcd->lcd_uuid[0] == '\0') {
			CDEBUG(D_INFO, "skipping zeroed client at offset %d\n",
			       cl_idx);
			continue;
		}

		last_transno = lcd_last_transno(lcd);

		/* These exports are cleaned up by disconnect, so they
		 * need to be set up like real exports as connect does.
		 */
		CDEBUG(D_HA, "RCVRNG CLIENT uuid: %s idx: %d lr: "LPU64
		       " srv lr: "LPU64" lx: "LPU64"\n", lcd->lcd_uuid, cl_idx,
		       last_transno, lsd->lsd_last_transno, lcd_last_xid(lcd));

		exp = class_new_export(obd, (struct obd_uuid *)lcd->lcd_uuid);
		if (IS_ERR(exp)) {
			if (PTR_ERR(exp) == -EALREADY) {
				/* export already exists, zero out this one */
				CERROR("%s: Duplicate export %s!\n",
				       tgt_name(tgt), lcd->lcd_uuid);
				continue;
			}
			GOTO(err_out, rc = PTR_ERR(exp));
		}

		ted = &exp->exp_target_data;
		*ted->ted_lcd = *lcd;

		rc = tgt_client_add(env, exp, cl_idx);
		LASSERTF(rc == 0, "rc = %d\n", rc); /* can't fail existing */
		/* VBR: set export last committed version */
		exp->exp_last_committed = last_transno;
		spin_lock(&exp->exp_lock);
		exp->exp_connecting = 0;
		exp->exp_in_recovery = 0;
		spin_unlock(&exp->exp_lock);
		obd->obd_max_recoverable_clients++;
		class_export_put(exp);

		/* Need to check last_rcvd even for duplicated exports. */
		CDEBUG(D_OTHER, "client at idx %d has last_transno = "LPU64"\n",
		       cl_idx, last_transno);

		spin_lock(&tgt->lut_translock);
		tgt->lut_last_transno = max(last_transno,
					    tgt->lut_last_transno);
		spin_unlock(&tgt->lut_translock);
	}

err_out:
	OBD_FREE_PTR(lcd);
	RETURN(rc);
}

struct server_compat_data {
	__u32 rocompat;
	__u32 incompat;
	__u32 rocinit;
	__u32 incinit;
};

static struct server_compat_data tgt_scd[] = {
	[LDD_F_SV_TYPE_MDT] = {
		.rocompat = OBD_ROCOMPAT_LOVOBJID,
		.incompat = OBD_INCOMPAT_MDT | OBD_INCOMPAT_COMMON_LR |
			    OBD_INCOMPAT_FID | OBD_INCOMPAT_IAM_DIR |
			    OBD_INCOMPAT_LMM_VER | OBD_INCOMPAT_MULTI_OI,
		.rocinit = OBD_ROCOMPAT_LOVOBJID,
		.incinit = OBD_INCOMPAT_MDT | OBD_INCOMPAT_COMMON_LR |
			   OBD_INCOMPAT_MULTI_OI,
	},
	[LDD_F_SV_TYPE_OST] = {
		.rocompat = OBD_ROCOMPAT_IDX_IN_IDIF,
		.incompat = OBD_INCOMPAT_OST | OBD_INCOMPAT_COMMON_LR |
			    OBD_INCOMPAT_FID,
		.rocinit = OBD_ROCOMPAT_IDX_IN_IDIF,
		.incinit = OBD_INCOMPAT_OST | OBD_INCOMPAT_COMMON_LR,
	}
};

int tgt_server_data_init(const struct lu_env *env, struct lu_target *tgt)
{
	struct tgt_thread_info		*tti = tgt_th_info(env);
	struct lr_server_data		*lsd = &tgt->lut_lsd;
	unsigned long			 last_rcvd_size;
	__u32				 index;
	int				 rc, type;

	rc = dt_attr_get(env, tgt->lut_last_rcvd, &tti->tti_attr);
	if (rc)
		RETURN(rc);

	last_rcvd_size = (unsigned long)tti->tti_attr.la_size;

	/* ensure padding in the struct is the correct size */
	CLASSERT(offsetof(struct lr_server_data, lsd_padding) +
		 sizeof(lsd->lsd_padding) == LR_SERVER_SIZE);

	rc = server_name2index(tgt_name(tgt), &index, NULL);
	if (rc < 0) {
		CERROR("%s: Can not get index from name: rc = %d\n",
		       tgt_name(tgt), rc);
		RETURN(rc);
	}
	/* server_name2index() returns type */
	type = rc;
	if (type != LDD_F_SV_TYPE_MDT && type != LDD_F_SV_TYPE_OST) {
		CERROR("%s: unknown target type %x\n", tgt_name(tgt), type);
		RETURN(-EINVAL);
	}

	/* last_rcvd on OST doesn't provide reconstruct support because there
	 * may be up to 8 in-flight write requests per single slot in
	 * last_rcvd client data
	 */
	tgt->lut_no_reconstruct = (type == LDD_F_SV_TYPE_OST);

	if (last_rcvd_size == 0) {
		LCONSOLE_WARN("%s: new disk, initializing\n", tgt_name(tgt));

		memcpy(lsd->lsd_uuid, tgt->lut_obd->obd_uuid.uuid,
		       sizeof(lsd->lsd_uuid));
		lsd->lsd_last_transno = 0;
		lsd->lsd_mount_count = 0;
		lsd->lsd_server_size = LR_SERVER_SIZE;
		lsd->lsd_client_start = LR_CLIENT_START;
		lsd->lsd_client_size = LR_CLIENT_SIZE;
		lsd->lsd_subdir_count = OBJ_SUBDIR_COUNT;
		lsd->lsd_osd_index = index;
		lsd->lsd_feature_rocompat = tgt_scd[type].rocinit;
		lsd->lsd_feature_incompat = tgt_scd[type].incinit;
	} else {
		rc = tgt_server_data_read(env, tgt);
		if (rc) {
			CERROR("%s: error reading LAST_RCVD: rc= %d\n",
			       tgt_name(tgt), rc);
			RETURN(rc);
		}
		if (strcmp(lsd->lsd_uuid, tgt->lut_obd->obd_uuid.uuid)) {
			LCONSOLE_ERROR_MSG(0x157, "Trying to start OBD %s "
					   "using the wrong disk %s. Were the"
					   " /dev/ assignments rearranged?\n",
					   tgt->lut_obd->obd_uuid.uuid,
					   lsd->lsd_uuid);
			RETURN(-EINVAL);
		}

		if (lsd->lsd_osd_index != index) {
			LCONSOLE_ERROR_MSG(0x157, "%s: index %d in last rcvd "
					   "is different with the index %d in"
					   "config log, It might be disk"
					   "corruption!\n", tgt_name(tgt),
					   lsd->lsd_osd_index, index);
			RETURN(-EINVAL);
		}
	}

	if (lsd->lsd_feature_incompat & ~tgt_scd[type].incompat) {
		CERROR("%s: unsupported incompat filesystem feature(s) %x\n",
		       tgt_name(tgt),
		       lsd->lsd_feature_incompat & ~tgt_scd[type].incompat);
		RETURN(-EINVAL);
	}

	if (type == LDD_F_SV_TYPE_MDT)
		lsd->lsd_feature_incompat |= OBD_INCOMPAT_FID;

	if (lsd->lsd_feature_rocompat & ~tgt_scd[type].rocompat) {
		CERROR("%s: unsupported read-only filesystem feature(s) %x\n",
		       tgt_name(tgt),
		       lsd->lsd_feature_rocompat & ~tgt_scd[type].rocompat);
		RETURN(-EINVAL);
	}
	/** Interop: evict all clients at first boot with 1.8 last_rcvd */
	if (type == LDD_F_SV_TYPE_MDT &&
	    !(lsd->lsd_feature_compat & OBD_COMPAT_20)) {
		if (last_rcvd_size > lsd->lsd_client_start) {
			LCONSOLE_WARN("%s: mounting at first time on 1.8 FS, "
				      "remove all clients for interop needs\n",
				      tgt_name(tgt));
			rc = tgt_truncate_last_rcvd(env, tgt,
						    lsd->lsd_client_start);
			if (rc)
				RETURN(rc);
			last_rcvd_size = lsd->lsd_client_start;
		}
		/** set 2.0 flag to upgrade/downgrade between 1.8 and 2.0 */
		lsd->lsd_feature_compat |= OBD_COMPAT_20;
	}

	spin_lock(&tgt->lut_translock);
	tgt->lut_last_transno = lsd->lsd_last_transno;
	spin_unlock(&tgt->lut_translock);

	lsd->lsd_mount_count++;

	CDEBUG(D_INODE, "=======,=BEGIN DUMPING LAST_RCVD========\n");
	CDEBUG(D_INODE, "%s: server last_transno: "LPU64"\n",
	       tgt_name(tgt), tgt->lut_last_transno);
	CDEBUG(D_INODE, "%s: server mount_count: "LPU64"\n",
	       tgt_name(tgt), lsd->lsd_mount_count);
	CDEBUG(D_INODE, "%s: server data size: %u\n",
	       tgt_name(tgt), lsd->lsd_server_size);
	CDEBUG(D_INODE, "%s: per-client data start: %u\n",
	       tgt_name(tgt), lsd->lsd_client_start);
	CDEBUG(D_INODE, "%s: per-client data size: %u\n",
	       tgt_name(tgt), lsd->lsd_client_size);
	CDEBUG(D_INODE, "%s: last_rcvd size: %lu\n",
	       tgt_name(tgt), last_rcvd_size);
	CDEBUG(D_INODE, "%s: server subdir_count: %u\n",
	       tgt_name(tgt), lsd->lsd_subdir_count);
	CDEBUG(D_INODE, "%s: last_rcvd clients: %lu\n", tgt_name(tgt),
	       last_rcvd_size <= lsd->lsd_client_start ? 0 :
	       (last_rcvd_size - lsd->lsd_client_start) /
		lsd->lsd_client_size);
	CDEBUG(D_INODE, "========END DUMPING LAST_RCVD========\n");

	if (lsd->lsd_server_size == 0 || lsd->lsd_client_start == 0 ||
	    lsd->lsd_client_size == 0) {
		CERROR("%s: bad last_rcvd contents!\n", tgt_name(tgt));
		RETURN(-EINVAL);
	}

	if (!tgt->lut_obd->obd_replayable)
		CWARN("%s: recovery support OFF\n", tgt_name(tgt));

	rc = tgt_clients_data_init(env, tgt, last_rcvd_size);
	if (rc < 0)
		GOTO(err_client, rc);

	spin_lock(&tgt->lut_translock);
	/* obd_last_committed is used for compatibility
	 * with other lustre recovery code */
	tgt->lut_obd->obd_last_committed = tgt->lut_last_transno;
	spin_unlock(&tgt->lut_translock);

	tgt->lut_obd->u.obt.obt_mount_count = lsd->lsd_mount_count;
	tgt->lut_obd->u.obt.obt_instance = (__u32)lsd->lsd_mount_count;

	/* save it, so mount count and last_transno is current */
	rc = tgt_server_data_update(env, tgt, 0);
	if (rc < 0)
		GOTO(err_client, rc);

	RETURN(0);

err_client:
	class_disconnect_exports(tgt->lut_obd);
	return rc;
}

/* add credits for last_rcvd update */
int tgt_txn_start_cb(const struct lu_env *env, struct thandle *th,
		     void *cookie)
{
	struct lu_target	*tgt = cookie;
	struct tgt_session_info	*tsi;
	struct tgt_thread_info	*tti = tgt_th_info(env);
	int			 rc;

	/* if there is no session, then this transaction is not result of
	 * request processing but some local operation */
	if (env->le_ses == NULL)
		return 0;

	LASSERT(tgt->lut_last_rcvd);
	tsi = tgt_ses_info(env);
	/* OFD may start transaction without export assigned */
	if (tsi->tsi_exp == NULL)
		return 0;

	tti_buf_lcd(tti);
	rc = dt_declare_record_write(env, tgt->lut_last_rcvd,
				     &tti->tti_buf,
				     tsi->tsi_exp->exp_target_data.ted_lr_off,
				     th);
	if (rc)
		return rc;

	tti_buf_lsd(tti);
	rc = dt_declare_record_write(env, tgt->lut_last_rcvd,
				     &tti->tti_buf, 0, th);
	if (rc)
		return rc;

	if (tsi->tsi_vbr_obj != NULL &&
	    !lu_object_remote(&tsi->tsi_vbr_obj->do_lu))
		rc = dt_declare_version_set(env, tsi->tsi_vbr_obj, th);

	return rc;
}

/* Update last_rcvd records with latests transaction data */
int tgt_txn_stop_cb(const struct lu_env *env, struct thandle *th,
		    void *cookie)
{
	struct lu_target	*tgt = cookie;
	struct tgt_session_info	*tsi;
	struct tgt_thread_info	*tti = tgt_th_info(env);
	struct dt_object	*obj = NULL;
	int			 rc;
	bool			 echo_client;

	if (env->le_ses == NULL)
		return 0;

	tsi = tgt_ses_info(env);
	/* OFD may start transaction without export assigned */
	if (tsi->tsi_exp == NULL)
		return 0;

	echo_client = (tgt_ses_req(tsi) == NULL);

	if (tti->tti_has_trans && !echo_client) {
		if (tti->tti_mult_trans == 0) {
			CDEBUG(D_HA, "More than one transaction "LPU64"\n",
			       tti->tti_transno);
			RETURN(0);
		}
		/* we need another transno to be assigned */
		tti->tti_transno = 0;
	} else if (th->th_result == 0) {
		tti->tti_has_trans = 1;
	}

	if (tsi->tsi_vbr_obj != NULL &&
	    !lu_object_remote(&tsi->tsi_vbr_obj->do_lu)) {
		obj = tsi->tsi_vbr_obj;
	}

	if (unlikely(echo_client)) /* echo client special case */
		rc = tgt_last_rcvd_update_echo(env, tgt, obj, th,
					       tsi->tsi_exp);
	else
		rc = tgt_last_rcvd_update(env, tgt, obj, tsi->tsi_opdata, th,
					  tgt_ses_req(tsi));
	return rc;
}
