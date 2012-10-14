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
 * Copyright (c) 2011, 2012, Whamcloud, Inc.
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
int lut_client_alloc(struct obd_export *exp)
{
        LASSERT(exp != exp->exp_obd->obd_self_export);

        OBD_ALLOC_PTR(exp->exp_target_data.ted_lcd);
        if (exp->exp_target_data.ted_lcd == NULL)
                RETURN(-ENOMEM);
        /* Mark that slot is not yet valid, 0 doesn't work here */
        exp->exp_target_data.ted_lr_idx = -1;
        RETURN(0);
}
EXPORT_SYMBOL(lut_client_alloc);

/**
 * Free in-memory data for client slot related to export.
 */
void lut_client_free(struct obd_export *exp)
{
        struct tg_export_data *ted = &exp->exp_target_data;
        struct lu_target *lut = class_exp2tgt(exp);

        LASSERT(exp != exp->exp_obd->obd_self_export);

        OBD_FREE_PTR(ted->ted_lcd);
        ted->ted_lcd = NULL;

        /* Slot may be not yet assigned */
        if (ted->ted_lr_idx < 0)
                return;
        /* Clear bit when lcd is freed */
	LASSERT(lut->lut_client_bitmap);
        if (!cfs_test_and_clear_bit(ted->ted_lr_idx, lut->lut_client_bitmap)) {
                CERROR("%s: client %u bit already clear in bitmap\n",
                       exp->exp_obd->obd_name, ted->ted_lr_idx);
                LBUG();
        }
}
EXPORT_SYMBOL(lut_client_free);

int lut_client_data_read(const struct lu_env *env, struct lu_target *tg,
			 struct lsd_client_data *lcd, loff_t *off, int index)
{
	struct tgt_thread_info *tti = tgt_th_info(env);
	int rc;

	tti_buf_lcd(tti);
	rc = dt_record_read(env, tg->lut_last_rcvd, &tti->tti_buf, off);
	if (rc == 0) {
		check_lcd(tg->lut_obd->obd_name, index, &tti->tti_lcd);
		lcd_le_to_cpu(&tti->tti_lcd, lcd);
	}

	CDEBUG(D_INFO, "%s: read lcd @%lld uuid = %s, last_transno = "LPU64
	       ", last_xid = "LPU64", last_result = %u, last_data = %u, "
	       "last_close_transno = "LPU64", last_close_xid = "LPU64", "
	       "last_close_result = %u, rc = %d\n", tg->lut_obd->obd_name,
	       *off, lcd->lcd_uuid, lcd->lcd_last_transno, lcd->lcd_last_xid,
	       lcd->lcd_last_result, lcd->lcd_last_data,
	       lcd->lcd_last_close_transno, lcd->lcd_last_close_xid,
	       lcd->lcd_last_close_result, rc);
	return rc;
}
EXPORT_SYMBOL(lut_client_data_read);

int lut_client_data_write(const struct lu_env *env, struct lu_target *tg,
			  struct lsd_client_data *lcd, loff_t *off,
			  struct thandle *th)
{
	struct tgt_thread_info *tti = tgt_th_info(env);

	lcd_cpu_to_le(lcd, &tti->tti_lcd);
	tti_buf_lcd(tti);

	return dt_record_write(env, tg->lut_last_rcvd, &tti->tti_buf, off, th);
}
EXPORT_SYMBOL(lut_client_data_write);

/**
 * Update client data in last_rcvd
 */
int lut_client_data_update(const struct lu_env *env, struct obd_export *exp)
{
	struct tg_export_data *ted = &exp->exp_target_data;
	struct lu_target      *tg = class_exp2tgt(exp);
	struct tgt_thread_info *tti = tgt_th_info(env);
	struct thandle	      *th;
	int		       rc = 0;

	ENTRY;

	th = dt_trans_create(env, tg->lut_bottom);
	if (IS_ERR(th))
		RETURN(PTR_ERR(th));

	rc = dt_declare_record_write(env, tg->lut_last_rcvd,
				     sizeof(struct lsd_client_data),
				     ted->ted_lr_off, th);
	if (rc)
		GOTO(out, rc);

	rc = dt_trans_start_local(env, tg->lut_bottom, th);
	if (rc)
		GOTO(out, rc);
	/*
	 * Until this operations will be committed the sync is needed
	 * for this export. This should be done _after_ starting the
	 * transaction so that many connecting clients will not bring
	 * server down with lots of sync writes.
	 */
	rc = lut_new_client_cb_add(th, exp);
	if (rc) {
		/* can't add callback, do sync now */
		th->th_sync = 1;
	} else {
		cfs_spin_lock(&exp->exp_lock);
		exp->exp_need_sync = 1;
		cfs_spin_unlock(&exp->exp_lock);
	}

	tti->tti_off = ted->ted_lr_off;
	rc = lut_client_data_write(env, tg, ted->ted_lcd, &tti->tti_off, th);
	EXIT;
out:
	dt_trans_stop(env, tg->lut_bottom, th);
	CDEBUG(D_INFO, "%s: update last_rcvd client data for UUID = %s, "
	       "last_transno = "LPU64": rc = %d\n", tg->lut_obd->obd_name,
	       tg->lut_lsd.lsd_uuid, tg->lut_lsd.lsd_last_transno, rc);

	return rc;
}

int lut_server_data_read(const struct lu_env *env, struct lu_target *tg)
{
	struct tgt_thread_info *tti = tgt_th_info(env);
	int rc;

	tti->tti_off = 0;
	tti_buf_lsd(tti);
	rc = dt_record_read(env, tg->lut_last_rcvd, &tti->tti_buf, &tti->tti_off);
	if (rc == 0)
		lsd_le_to_cpu(&tti->tti_lsd, &tg->lut_lsd);

	CDEBUG(D_INFO, "%s: read last_rcvd server data for UUID = %s, "
	       "last_transno = "LPU64": rc = %d\n", tg->lut_obd->obd_name,
	       tg->lut_lsd.lsd_uuid, tg->lut_lsd.lsd_last_transno, rc);
        return rc;
}
EXPORT_SYMBOL(lut_server_data_read);

int lut_server_data_write(const struct lu_env *env, struct lu_target *tg,
			  struct thandle *th)
{
	struct tgt_thread_info *tti = tgt_th_info(env);
	int rc;
	ENTRY;

	tti->tti_off = 0;
	tti_buf_lsd(tti);
	lsd_cpu_to_le(&tg->lut_lsd, &tti->tti_lsd);

	rc = dt_record_write(env, tg->lut_last_rcvd, &tti->tti_buf,
			     &tti->tti_off, th);

	CDEBUG(D_INFO, "%s: write last_rcvd server data for UUID = %s, "
	       "last_transno = "LPU64": rc = %d\n", tg->lut_obd->obd_name,
	       tg->lut_lsd.lsd_uuid, tg->lut_lsd.lsd_last_transno, rc);

	RETURN(rc);
}
EXPORT_SYMBOL(lut_server_data_write);

/**
 * Update server data in last_rcvd
 */
int lut_server_data_update(const struct lu_env *env, struct lu_target *tg,
			   int sync)
{
	struct tgt_thread_info *tti = tgt_th_info(env);
	struct thandle	*th;
	int		    rc = 0;

	ENTRY;

	CDEBUG(D_SUPER,
	       "%s: mount_count is "LPU64", last_transno is "LPU64"\n",
	       tg->lut_lsd.lsd_uuid, tg->lut_obd->u.obt.obt_mount_count,
	       tg->lut_last_transno);

	/* Always save latest transno to keep it fresh */
	cfs_spin_lock(&tg->lut_translock);
	tg->lut_lsd.lsd_last_transno = tg->lut_last_transno;
	cfs_spin_unlock(&tg->lut_translock);

	th = dt_trans_create(env, tg->lut_bottom);
	if (IS_ERR(th))
		RETURN(PTR_ERR(th));

	th->th_sync = sync;

	rc = dt_declare_record_write(env, tg->lut_last_rcvd,
				     sizeof(struct lr_server_data),
				     tti->tti_off, th);
	if (rc)
		GOTO(out, rc);

	rc = dt_trans_start(env, tg->lut_bottom, th);
	if (rc)
		GOTO(out, rc);

	rc = lut_server_data_write(env, tg, th);
out:
	dt_trans_stop(env, tg->lut_bottom, th);

	CDEBUG(D_INFO, "%s: update last_rcvd server data for UUID = %s, "
	       "last_transno = "LPU64": rc = %d\n", tg->lut_obd->obd_name,
	       tg->lut_lsd.lsd_uuid, tg->lut_lsd.lsd_last_transno, rc);
	RETURN(rc);
}
EXPORT_SYMBOL(lut_server_data_update);

int lut_truncate_last_rcvd(const struct lu_env *env, struct lu_target *tg,
			   loff_t size)
{
	struct dt_object *dt = tg->lut_last_rcvd;
	struct thandle	 *th;
	struct lu_attr	  attr;
	int		  rc;

	ENTRY;

	attr.la_size = size;
	attr.la_valid = LA_SIZE;

	th = dt_trans_create(env, tg->lut_bottom);
	if (IS_ERR(th))
		RETURN(PTR_ERR(th));
	rc = dt_declare_punch(env, dt, size, OBD_OBJECT_EOF, th);
	if (rc)
		GOTO(cleanup, rc);
	rc = dt_declare_attr_set(env, dt, &attr, th);
	if (rc)
		GOTO(cleanup, rc);
	rc = dt_trans_start_local(env, tg->lut_bottom, th);
	if (rc)
		GOTO(cleanup, rc);

	rc = dt_punch(env, dt, size, OBD_OBJECT_EOF, th, BYPASS_CAPA);
	if (rc == 0)
		rc = dt_attr_set(env, dt, &attr, th, BYPASS_CAPA);

cleanup:
	dt_trans_stop(env, tg->lut_bottom, th);

	RETURN(rc);
}
EXPORT_SYMBOL(lut_truncate_last_rcvd);

void lut_client_epoch_update(const struct lu_env *env, struct obd_export *exp)
{
        struct lsd_client_data *lcd = exp->exp_target_data.ted_lcd;
        struct lu_target *lut = class_exp2tgt(exp);

        LASSERT(lut->lut_bottom);
        /** VBR: set client last_epoch to current epoch */
        if (lcd->lcd_last_epoch >= lut->lut_lsd.lsd_start_epoch)
                return;
        lcd->lcd_last_epoch = lut->lut_lsd.lsd_start_epoch;
        lut_client_data_update(env, exp);
}

/**
 * Update boot epoch when recovery ends
 */
void lut_boot_epoch_update(struct lu_target *lut)
{
        struct lu_env env;
        struct ptlrpc_request *req;
        __u32 start_epoch;
        cfs_list_t client_list;
        int rc;

        if (lut->lut_obd->obd_stopping)
                return;

	rc = lu_env_init(&env, LCT_DT_THREAD);
        if (rc) {
                CERROR("Can't initialize environment rc=%d\n", rc);
                return;
        }

        cfs_spin_lock(&lut->lut_translock);
        start_epoch = lr_epoch(lut->lut_last_transno) + 1;
        lut->lut_last_transno = (__u64)start_epoch << LR_EPOCH_BITS;
        lut->lut_lsd.lsd_start_epoch = start_epoch;
        cfs_spin_unlock(&lut->lut_translock);

        CFS_INIT_LIST_HEAD(&client_list);
        /**
         * The recovery is not yet finished and final queue can still be updated
         * with resend requests. Move final list to separate one for processing
         */
        cfs_spin_lock(&lut->lut_obd->obd_recovery_task_lock);
        cfs_list_splice_init(&lut->lut_obd->obd_final_req_queue, &client_list);
        cfs_spin_unlock(&lut->lut_obd->obd_recovery_task_lock);

        /**
         * go through list of exports participated in recovery and
         * set new epoch for them
         */
        cfs_list_for_each_entry(req, &client_list, rq_list) {
                LASSERT(!req->rq_export->exp_delayed);
                if (!req->rq_export->exp_vbr_failed)
                        lut_client_epoch_update(&env, req->rq_export);
        }
        /** return list back at once */
        cfs_spin_lock(&lut->lut_obd->obd_recovery_task_lock);
        cfs_list_splice_init(&client_list, &lut->lut_obd->obd_final_req_queue);
        cfs_spin_unlock(&lut->lut_obd->obd_recovery_task_lock);
        /** update server epoch */
        lut_server_data_update(&env, lut, 1);
        lu_env_fini(&env);
}
EXPORT_SYMBOL(lut_boot_epoch_update);

/**
 * commit callback, need to update last_commited value
 */
struct lut_last_committed_callback {
        struct dt_txn_commit_cb llcc_cb;
        struct lu_target       *llcc_lut;
        struct obd_export      *llcc_exp;
        __u64                   llcc_transno;
};

void lut_cb_last_committed(struct lu_env *env, struct thandle *th,
                           struct dt_txn_commit_cb *cb, int err)
{
        struct lut_last_committed_callback *ccb;

        ccb = container_of0(cb, struct lut_last_committed_callback, llcc_cb);

	LASSERT(ccb->llcc_lut != NULL);
	LASSERT(ccb->llcc_exp->exp_obd == ccb->llcc_lut->lut_obd);

        cfs_spin_lock(&ccb->llcc_lut->lut_translock);
        if (ccb->llcc_transno > ccb->llcc_lut->lut_obd->obd_last_committed)
                ccb->llcc_lut->lut_obd->obd_last_committed = ccb->llcc_transno;

        LASSERT(ccb->llcc_exp);
        if (ccb->llcc_transno > ccb->llcc_exp->exp_last_committed) {
                ccb->llcc_exp->exp_last_committed = ccb->llcc_transno;
                cfs_spin_unlock(&ccb->llcc_lut->lut_translock);
                ptlrpc_commit_replies(ccb->llcc_exp);
        } else {
                cfs_spin_unlock(&ccb->llcc_lut->lut_translock);
        }
        class_export_cb_put(ccb->llcc_exp);
        if (ccb->llcc_transno)
                CDEBUG(D_HA, "%s: transno "LPD64" is committed\n",
                       ccb->llcc_lut->lut_obd->obd_name, ccb->llcc_transno);
        OBD_FREE_PTR(ccb);
}

int lut_last_commit_cb_add(struct thandle *th, struct lu_target *lut,
                           struct obd_export *exp, __u64 transno)
{
	struct lut_last_committed_callback *ccb;
	struct dt_txn_commit_cb		   *dcb;
	int				   rc;

	OBD_ALLOC_PTR(ccb);
	if (ccb == NULL)
		return -ENOMEM;

	ccb->llcc_lut	  = lut;
	ccb->llcc_exp	  = class_export_cb_get(exp);
	ccb->llcc_transno = transno;

	dcb	       = &ccb->llcc_cb;
	dcb->dcb_func  = lut_cb_last_committed;
	CFS_INIT_LIST_HEAD(&dcb->dcb_linkage);
	strncpy(dcb->dcb_name, "lut_cb_last_committed", MAX_COMMIT_CB_STR_LEN);
	dcb->dcb_name[MAX_COMMIT_CB_STR_LEN - 1] = '\0';

	rc = dt_trans_cb_add(th, dcb);
	if (rc) {
		class_export_cb_put(exp);
		OBD_FREE_PTR(ccb);
	}

	if ((exp->exp_connect_flags & OBD_CONNECT_LIGHTWEIGHT) != 0)
		/* report failure to force synchronous operation */
		return -EPERM;

	return rc;
}
EXPORT_SYMBOL(lut_last_commit_cb_add);

struct lut_new_client_callback {
        struct dt_txn_commit_cb lncc_cb;
        struct obd_export      *lncc_exp;
};

void lut_cb_new_client(struct lu_env *env, struct thandle *th,
                       struct dt_txn_commit_cb *cb, int err)
{
        struct lut_new_client_callback *ccb;

        ccb = container_of0(cb, struct lut_new_client_callback, lncc_cb);

        LASSERT(ccb->lncc_exp->exp_obd);

        CDEBUG(D_RPCTRACE, "%s: committing for initial connect of %s\n",
               ccb->lncc_exp->exp_obd->obd_name,
               ccb->lncc_exp->exp_client_uuid.uuid);

        cfs_spin_lock(&ccb->lncc_exp->exp_lock);
        ccb->lncc_exp->exp_need_sync = 0;
        cfs_spin_unlock(&ccb->lncc_exp->exp_lock);
        class_export_cb_put(ccb->lncc_exp);

        OBD_FREE_PTR(ccb);
}

int lut_new_client_cb_add(struct thandle *th, struct obd_export *exp)
{
	struct lut_new_client_callback *ccb;
	struct dt_txn_commit_cb	       *dcb;
	int			       rc;

	OBD_ALLOC_PTR(ccb);
	if (ccb == NULL)
		return -ENOMEM;

	ccb->lncc_exp  = class_export_cb_get(exp);

	dcb	       = &ccb->lncc_cb;
	dcb->dcb_func  = lut_cb_new_client;
	CFS_INIT_LIST_HEAD(&dcb->dcb_linkage);
	strncpy(dcb->dcb_name, "lut_cb_new_client", MAX_COMMIT_CB_STR_LEN);
	dcb->dcb_name[MAX_COMMIT_CB_STR_LEN - 1] = '\0';

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
int lut_client_new(const struct lu_env *env, struct obd_export *exp)
{
	struct tg_export_data *ted = &exp->exp_target_data;
	struct lu_target *tg = class_exp2tgt(exp);
	int rc = 0, idx;

	ENTRY;

	LASSERT(tg->lut_client_bitmap != NULL);
	if (!strcmp(ted->ted_lcd->lcd_uuid, tg->lut_obd->obd_uuid.uuid))
		RETURN(0);

	cfs_mutex_init(&ted->ted_lcd_lock);

	if ((exp->exp_connect_flags & OBD_CONNECT_LIGHTWEIGHT) != 0)
		RETURN(0);

	/* the bitmap operations can handle cl_idx > sizeof(long) * 8, so
	 * there's no need for extra complication here
	 */
	idx = cfs_find_first_zero_bit(tg->lut_client_bitmap, LR_MAX_CLIENTS);
repeat:
	if (idx >= LR_MAX_CLIENTS ||
	    OBD_FAIL_CHECK(OBD_FAIL_MDS_CLIENT_ADD)) {
		CERROR("%s: no room for %u clients - fix LR_MAX_CLIENTS\n",
		       tg->lut_obd->obd_name,  idx);
		RETURN(-EOVERFLOW);
	}
	if (cfs_test_and_set_bit(idx, tg->lut_client_bitmap)) {
		idx = cfs_find_next_zero_bit(tg->lut_client_bitmap,
					     LR_MAX_CLIENTS, idx);
		goto repeat;
	}

	CDEBUG(D_INFO, "%s: client at idx %d with UUID '%s' added\n",
	       tg->lut_obd->obd_name, idx, ted->ted_lcd->lcd_uuid);

	ted->ted_lr_idx = idx;
	ted->ted_lr_off = tg->lut_lsd.lsd_client_start +
			  idx * tg->lut_lsd.lsd_client_size;

	LASSERTF(ted->ted_lr_off > 0, "ted_lr_off = %llu\n", ted->ted_lr_off);

	CDEBUG(D_INFO, "%s: new client at index %d (%llu) with UUID '%s'\n",
	       tg->lut_obd->obd_name, ted->ted_lr_idx, ted->ted_lr_off,
	       ted->ted_lcd->lcd_uuid);

	if (OBD_FAIL_CHECK(OBD_FAIL_TGT_CLIENT_ADD))
		RETURN(-ENOSPC);

	rc = lut_client_data_update(env, exp);
	if (rc)
		CERROR("%s: Failed to write client lcd at idx %d, rc %d\n",
		       tg->lut_obd->obd_name, idx, rc);

	RETURN(rc);
}
EXPORT_SYMBOL(lut_client_new);

/* Add client data to the MDS.  We use a bitmap to locate a free space
 * in the last_rcvd file if cl_off is -1 (i.e. a new client).
 * Otherwise, we just have to read the data from the last_rcvd file and
 * we know its offset.
 *
 * It should not be possible to fail adding an existing client - otherwise
 * mdt_init_server_data() callsite needs to be fixed.
 */
int lut_client_add(const struct lu_env *env,  struct obd_export *exp, int idx)
{
	struct tg_export_data *ted = &exp->exp_target_data;
	struct lu_target *tg = class_exp2tgt(exp);

	ENTRY;

	LASSERT(tg->lut_client_bitmap != NULL);
	LASSERTF(idx >= 0, "%d\n", idx);

	if (!strcmp(ted->ted_lcd->lcd_uuid, tg->lut_obd->obd_uuid.uuid) ||
	    (exp->exp_connect_flags & OBD_CONNECT_LIGHTWEIGHT) != 0)
		RETURN(0);

	if (cfs_test_and_set_bit(idx, tg->lut_client_bitmap)) {
		CERROR("%s: client %d: bit already set in bitmap!!\n",
		       tg->lut_obd->obd_name,  idx);
		LBUG();
	}

	CDEBUG(D_INFO, "%s: client at idx %d with UUID '%s' added\n",
	       tg->lut_obd->obd_name, idx, ted->ted_lcd->lcd_uuid);

	ted->ted_lr_idx = idx;
	ted->ted_lr_off = tg->lut_lsd.lsd_client_start +
			  idx * tg->lut_lsd.lsd_client_size;

	cfs_mutex_init(&ted->ted_lcd_lock);

	LASSERTF(ted->ted_lr_off > 0, "ted_lr_off = %llu\n", ted->ted_lr_off);

	RETURN(0);
}
EXPORT_SYMBOL(lut_client_add);

int lut_client_del(const struct lu_env *env, struct obd_export *exp)
{
	struct tg_export_data *ted = &exp->exp_target_data;
	struct lu_target      *tg = class_exp2tgt(exp);
	int		       rc;

	ENTRY;

	LASSERT(ted->ted_lcd);

	/* XXX if lcd_uuid were a real obd_uuid, I could use obd_uuid_equals */
	if (!strcmp((char *)ted->ted_lcd->lcd_uuid,
		    (char *)tg->lut_obd->obd_uuid.uuid) ||
	    (exp->exp_connect_flags & OBD_CONNECT_LIGHTWEIGHT) != 0)
		RETURN(0);

	CDEBUG(D_INFO, "%s: del client at idx %u, off %lld, UUID '%s'\n",
	       tg->lut_obd->obd_name, ted->ted_lr_idx, ted->ted_lr_off,
	       ted->ted_lcd->lcd_uuid);

	/* Clear the bit _after_ zeroing out the client so we don't
	   race with filter_client_add and zero out new clients.*/
	if (!cfs_test_bit(ted->ted_lr_idx, tg->lut_client_bitmap)) {
		CERROR("%s: client %u: bit already clear in bitmap!!\n",
		       tg->lut_obd->obd_name, ted->ted_lr_idx);
		LBUG();
	}

	/* Do not erase record for recoverable client. */
	if (exp->exp_flags & OBD_OPT_FAILOVER)
		RETURN(0);

	/* Make sure the server's last_transno is up to date.
	 * This should be done before zeroing client slot so last_transno will
	 * be in server data or in client data in case of failure */
	rc = lut_server_data_update(env, tg, 0);
	if (rc != 0) {
		CERROR("%s: failed to update server data, skip client %s "
		       "zeroing, rc %d\n", tg->lut_obd->obd_name,
		       ted->ted_lcd->lcd_uuid, rc);
		RETURN(rc);
	}

	cfs_mutex_lock(&ted->ted_lcd_lock);
	memset(ted->ted_lcd->lcd_uuid, 0, sizeof ted->ted_lcd->lcd_uuid);
	rc = lut_client_data_update(env, exp);
	cfs_mutex_unlock(&ted->ted_lcd_lock);

	CDEBUG(rc == 0 ? D_INFO : D_ERROR,
	       "%s: zeroing out client %s at idx %u (%llu), rc %d\n",
	       tg->lut_obd->obd_name, ted->ted_lcd->lcd_uuid,
	       ted->ted_lr_idx, ted->ted_lr_off, rc);
	RETURN(rc);
}
EXPORT_SYMBOL(lut_client_del);
