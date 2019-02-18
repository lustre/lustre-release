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
 * version 2 along with this program; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 021110-1307, USA
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2012, 2016, Intel Corporation.
 */
/*
 * lustre/target/tgt_main.c
 *
 * Lustre Unified Target main initialization code
 *
 * Author: Mikhail Pershin <mike.pershin@intel.com>
 */

#define DEBUG_SUBSYSTEM S_CLASS

#include <obd.h>
#include "tgt_internal.h"
#include "../ptlrpc/ptlrpc_internal.h"

/*
 * Save cross-MDT lock in lut_slc_locks.
 *
 * Lock R/W count is not saved, but released in unlock (not canceled remotely),
 * instead only a refcount is taken, so that the remote MDT where the object
 * resides can detect conflict with this lock there.
 *
 * \param lut target
 * \param lock cross-MDT lock to save
 * \param transno when the transaction with this transno is committed, this lock
 *		  can be canceled.
 */
void tgt_save_slc_lock(struct lu_target *lut, struct ldlm_lock *lock,
		       __u64 transno)
{
	spin_lock(&lut->lut_slc_locks_guard);
	lock_res_and_lock(lock);
	if (ldlm_is_cbpending(lock)) {
		/* if it was canceld by server, don't save, because remote MDT
		 * will do Sync-on-Cancel. */
		LDLM_LOCK_PUT(lock);
	} else {
		lock->l_transno = transno;
		/* if this lock is in the list already, there are two operations
		 * both use this lock, and save it after use, so for the second
		 * one, just put the refcount. */
		if (list_empty(&lock->l_slc_link))
			list_add_tail(&lock->l_slc_link, &lut->lut_slc_locks);
		else
			LDLM_LOCK_PUT(lock);
	}
	unlock_res_and_lock(lock);
	spin_unlock(&lut->lut_slc_locks_guard);
}
EXPORT_SYMBOL(tgt_save_slc_lock);

/*
 * Discard cross-MDT lock from lut_slc_locks.
 *
 * This is called upon BAST, just remove lock from lut_slc_locks and put lock
 * refcount. The BAST will cancel this lock.
 *
 * \param lut target
 * \param lock cross-MDT lock to discard
 */
void tgt_discard_slc_lock(struct lu_target *lut, struct ldlm_lock *lock)
{
	spin_lock(&lut->lut_slc_locks_guard);
	lock_res_and_lock(lock);
	/* may race with tgt_cancel_slc_locks() */
	if (lock->l_transno != 0) {
		LASSERT(!list_empty(&lock->l_slc_link));
		LASSERT(ldlm_is_cbpending(lock));
		list_del_init(&lock->l_slc_link);
		lock->l_transno = 0;
		LDLM_LOCK_PUT(lock);
	}
	unlock_res_and_lock(lock);
	spin_unlock(&lut->lut_slc_locks_guard);
}
EXPORT_SYMBOL(tgt_discard_slc_lock);

/*
 * Cancel cross-MDT locks upon transaction commit.
 *
 * Remove cross-MDT locks from lut_slc_locks, cancel them and put lock refcount.
 *
 * \param lut target
 * \param transno transaction with this number was committed.
 */
void tgt_cancel_slc_locks(struct lu_target *lut, __u64 transno)
{
	struct ldlm_lock *lock, *next;
	LIST_HEAD(list);
	struct lustre_handle lockh;

	spin_lock(&lut->lut_slc_locks_guard);
	list_for_each_entry_safe(lock, next, &lut->lut_slc_locks,
				 l_slc_link) {
		lock_res_and_lock(lock);
		LASSERT(lock->l_transno != 0);
		if (lock->l_transno > transno) {
			unlock_res_and_lock(lock);
			continue;
		}
		/* ouch, another operation is using it after it's saved */
		if (lock->l_readers != 0 || lock->l_writers != 0) {
			unlock_res_and_lock(lock);
			continue;
		}
		/* set CBPENDING so that this lock won't be used again */
		ldlm_set_cbpending(lock);
		lock->l_transno = 0;
		list_move(&lock->l_slc_link, &list);
		unlock_res_and_lock(lock);
	}
	spin_unlock(&lut->lut_slc_locks_guard);

	list_for_each_entry_safe(lock, next, &list, l_slc_link) {
		list_del_init(&lock->l_slc_link);
		ldlm_lock2handle(lock, &lockh);
		ldlm_cli_cancel(&lockh, LCF_ASYNC);
		LDLM_LOCK_PUT(lock);
	}
}

int tgt_init(const struct lu_env *env, struct lu_target *lut,
	     struct obd_device *obd, struct dt_device *dt,
	     struct tgt_opc_slice *slice, int request_fail_id,
	     int reply_fail_id)
{
	struct dt_object_format	 dof;
	struct lu_attr		 attr;
	struct lu_fid		 fid;
	struct dt_object	*o;
	int i, rc = 0;

	ENTRY;

	LASSERT(lut);
	LASSERT(obd);
	lut->lut_obd = obd;
	lut->lut_bottom = dt;
	lut->lut_last_rcvd = NULL;
	lut->lut_client_bitmap = NULL;
	atomic_set(&lut->lut_num_clients, 0);
	atomic_set(&lut->lut_client_generation, 0);
	lut->lut_reply_data = NULL;
	lut->lut_reply_bitmap = NULL;
	obd->u.obt.obt_lut = lut;
	obd->u.obt.obt_magic = OBT_MAGIC;

	/* set request handler slice and parameters */
	lut->lut_slice = slice;
	lut->lut_reply_fail_id = reply_fail_id;
	lut->lut_request_fail_id = request_fail_id;

	/* sptlrcp variables init */
	rwlock_init(&lut->lut_sptlrpc_lock);
	sptlrpc_rule_set_init(&lut->lut_sptlrpc_rset);

	spin_lock_init(&lut->lut_flags_lock);
	lut->lut_sync_lock_cancel = NEVER_SYNC_ON_CANCEL;

	spin_lock_init(&lut->lut_slc_locks_guard);
	INIT_LIST_HEAD(&lut->lut_slc_locks);

	/* last_rcvd initialization is needed by replayable targets only */
	if (!obd->obd_replayable)
		RETURN(0);

	spin_lock_init(&lut->lut_translock);
	spin_lock_init(&lut->lut_client_bitmap_lock);

	OBD_ALLOC(lut->lut_client_bitmap, LR_MAX_CLIENTS >> 3);
	if (lut->lut_client_bitmap == NULL)
		RETURN(-ENOMEM);

	memset(&attr, 0, sizeof(attr));
	attr.la_valid = LA_MODE;
	attr.la_mode = S_IFREG | S_IRUGO | S_IWUSR;
	dof.dof_type = dt_mode_to_dft(S_IFREG);

	lu_local_obj_fid(&fid, LAST_RECV_OID);

	o = dt_find_or_create(env, lut->lut_bottom, &fid, &dof, &attr);
	if (IS_ERR(o)) {
		rc = PTR_ERR(o);
		CERROR("%s: cannot open LAST_RCVD: rc = %d\n", tgt_name(lut),
		       rc);
		GOTO(out_put, rc);
	}

	lut->lut_last_rcvd = o;
	rc = tgt_server_data_init(env, lut);
	if (rc < 0)
		GOTO(out_put, rc);

	/* prepare transactions callbacks */
	lut->lut_txn_cb.dtc_txn_start = tgt_txn_start_cb;
	lut->lut_txn_cb.dtc_txn_stop = tgt_txn_stop_cb;
	lut->lut_txn_cb.dtc_cookie = lut;
	lut->lut_txn_cb.dtc_tag = LCT_DT_THREAD | LCT_MD_THREAD;
	INIT_LIST_HEAD(&lut->lut_txn_cb.dtc_linkage);

	dt_txn_callback_add(lut->lut_bottom, &lut->lut_txn_cb);
	lut->lut_bottom->dd_lu_dev.ld_site->ls_tgt = lut;

	/* reply_data is supported by MDT targets only for now */
	if (strncmp(obd->obd_type->typ_name, LUSTRE_MDT_NAME, 3) != 0)
		RETURN(0);

	OBD_ALLOC(lut->lut_reply_bitmap,
		  LUT_REPLY_SLOTS_MAX_CHUNKS * sizeof(unsigned long *));
	if (lut->lut_reply_bitmap == NULL)
		GOTO(out, rc = -ENOMEM);

	memset(&attr, 0, sizeof(attr));
	attr.la_valid = LA_MODE;
	attr.la_mode = S_IFREG | S_IRUGO | S_IWUSR;
	dof.dof_type = dt_mode_to_dft(S_IFREG);

	lu_local_obj_fid(&fid, REPLY_DATA_OID);

	o = dt_find_or_create(env, lut->lut_bottom, &fid, &dof, &attr);
	if (IS_ERR(o)) {
		rc = PTR_ERR(o);
		CERROR("%s: cannot open REPLY_DATA: rc = %d\n", tgt_name(lut),
		       rc);
		GOTO(out, rc);
	}
	lut->lut_reply_data = o;

	rc = tgt_reply_data_init(env, lut);
	if (rc < 0)
		GOTO(out, rc);

	atomic_set(&lut->lut_sync_count, 0);

	RETURN(0);

out:
	dt_txn_callback_del(lut->lut_bottom, &lut->lut_txn_cb);
out_put:
	obd->u.obt.obt_magic = 0;
	obd->u.obt.obt_lut = NULL;
	if (lut->lut_last_rcvd != NULL) {
		dt_object_put(env, lut->lut_last_rcvd);
		lut->lut_last_rcvd = NULL;
	}
	if (lut->lut_client_bitmap != NULL)
		OBD_FREE(lut->lut_client_bitmap, LR_MAX_CLIENTS >> 3);
	lut->lut_client_bitmap = NULL;
	if (lut->lut_reply_data != NULL)
		dt_object_put(env, lut->lut_reply_data);
	lut->lut_reply_data = NULL;
	if (lut->lut_reply_bitmap != NULL) {
		for (i = 0; i < LUT_REPLY_SLOTS_MAX_CHUNKS; i++) {
			if (lut->lut_reply_bitmap[i] != NULL)
				OBD_FREE_LARGE(lut->lut_reply_bitmap[i],
				    BITS_TO_LONGS(LUT_REPLY_SLOTS_PER_CHUNK) *
				    sizeof(long));
			lut->lut_reply_bitmap[i] = NULL;
		}
		OBD_FREE(lut->lut_reply_bitmap,
			 LUT_REPLY_SLOTS_MAX_CHUNKS * sizeof(unsigned long *));
	}
	lut->lut_reply_bitmap = NULL;
	return rc;
}
EXPORT_SYMBOL(tgt_init);

void tgt_fini(const struct lu_env *env, struct lu_target *lut)
{
	int i;
	int rc;
	ENTRY;

	if (lut->lut_lsd.lsd_feature_incompat & OBD_INCOMPAT_MULTI_RPCS &&
	    atomic_read(&lut->lut_num_clients) == 0) {
		/* Clear MULTI RPCS incompatibility flag that prevents previous
		 * Lustre versions to mount a target with reply_data file */
		lut->lut_lsd.lsd_feature_incompat &= ~OBD_INCOMPAT_MULTI_RPCS;
		rc = tgt_server_data_update(env, lut, 1);
		if (rc < 0)
			CERROR("%s: unable to clear MULTI RPCS "
			       "incompatibility flag\n",
			       lut->lut_obd->obd_name);
	}

	sptlrpc_rule_set_free(&lut->lut_sptlrpc_rset);

	if (lut->lut_reply_data != NULL)
		dt_object_put(env, lut->lut_reply_data);
	lut->lut_reply_data = NULL;
	if (lut->lut_reply_bitmap != NULL) {
		for (i = 0; i < LUT_REPLY_SLOTS_MAX_CHUNKS; i++) {
			if (lut->lut_reply_bitmap[i] != NULL)
				OBD_FREE_LARGE(lut->lut_reply_bitmap[i],
				    BITS_TO_LONGS(LUT_REPLY_SLOTS_PER_CHUNK) *
				    sizeof(long));
			lut->lut_reply_bitmap[i] = NULL;
		}
		OBD_FREE(lut->lut_reply_bitmap,
			 LUT_REPLY_SLOTS_MAX_CHUNKS * sizeof(unsigned long *));
	}
	lut->lut_reply_bitmap = NULL;
	if (lut->lut_client_bitmap) {
		OBD_FREE(lut->lut_client_bitmap, LR_MAX_CLIENTS >> 3);
		lut->lut_client_bitmap = NULL;
	}
	if (lut->lut_last_rcvd) {
		dt_txn_callback_del(lut->lut_bottom, &lut->lut_txn_cb);
		dt_object_put(env, lut->lut_last_rcvd);
		lut->lut_last_rcvd = NULL;
	}
	EXIT;
}
EXPORT_SYMBOL(tgt_fini);

/* context key constructor/destructor: tg_key_init, tg_key_fini */
LU_KEY_INIT(tgt, struct tgt_thread_info);

static void tgt_key_fini(const struct lu_context *ctx,
			 struct lu_context_key *key, void *data)
{
	struct tgt_thread_info		*info = data;
	struct thandle_exec_args	*args = &info->tti_tea;
	int				i;

	for (i = 0; i < args->ta_alloc_args; i++) {
		if (args->ta_args[i] != NULL)
			OBD_FREE_PTR(args->ta_args[i]);
	}

	if (args->ta_args != NULL)
		OBD_FREE(args->ta_args, sizeof(args->ta_args[0]) *
					args->ta_alloc_args);
	OBD_FREE_PTR(info);
}

static void tgt_key_exit(const struct lu_context *ctx,
			 struct lu_context_key *key, void *data)
{
	struct tgt_thread_info *tti = data;

	tti->tti_has_trans = 0;
	tti->tti_mult_trans = 0;
}

/* context key: tg_thread_key */
struct lu_context_key tgt_thread_key = {
	.lct_tags = LCT_MD_THREAD | LCT_DT_THREAD,
	.lct_init = tgt_key_init,
	.lct_fini = tgt_key_fini,
	.lct_exit = tgt_key_exit,
};

LU_KEY_INIT_GENERIC(tgt);

/* context key constructor/destructor: tgt_ses_key_init, tgt_ses_key_fini */
LU_KEY_INIT_FINI(tgt_ses, struct tgt_session_info);

/* context key: tgt_session_key */
struct lu_context_key tgt_session_key = {
	.lct_tags = LCT_SERVER_SESSION,
	.lct_init = tgt_ses_key_init,
	.lct_fini = tgt_ses_key_fini,
};
EXPORT_SYMBOL(tgt_session_key);

LU_KEY_INIT_GENERIC(tgt_ses);

/*
 * this page is allocated statically when module is initializing
 * it is used to simulate data corruptions, see ost_checksum_bulk()
 * for details. as the original pages provided by the layers below
 * can be remain in the internal cache, we do not want to modify
 * them.
 */
struct page *tgt_page_to_corrupt;

int tgt_mod_init(void)
{
	ENTRY;

	tgt_page_to_corrupt = alloc_page(GFP_KERNEL);

	tgt_key_init_generic(&tgt_thread_key, NULL);
	lu_context_key_register_many(&tgt_thread_key, NULL);

	tgt_ses_key_init_generic(&tgt_session_key, NULL);
	lu_context_key_register_many(&tgt_session_key, NULL);
	barrier_init();

	update_info_init();

	RETURN(0);
}

void tgt_mod_exit(void)
{
	barrier_fini();
	if (tgt_page_to_corrupt != NULL)
		put_page(tgt_page_to_corrupt);

	lu_context_key_degister(&tgt_thread_key);
	lu_context_key_degister(&tgt_session_key);
	update_info_fini();
}

