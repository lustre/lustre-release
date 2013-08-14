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
 * Copyright (c) 2012, 2013, Intel Corporation.
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

int tgt_init(const struct lu_env *env, struct lu_target *lut,
	     struct obd_device *obd, struct dt_device *dt,
	     struct tgt_opc_slice *slice, int request_fail_id,
	     int reply_fail_id)
{
	struct dt_object_format	 dof;
	struct lu_attr		 attr;
	struct lu_fid		 fid;
	struct dt_object	*o;
	int			 rc = 0;

	ENTRY;

	LASSERT(lut);
	LASSERT(obd);
	lut->lut_obd = obd;
	lut->lut_bottom = dt;
	lut->lut_last_rcvd = NULL;
	lut->lut_client_bitmap = NULL;
	obd->u.obt.obt_lut = lut;
	obd->u.obt.obt_magic = OBT_MAGIC;

	/* set request handler slice and parameters */
	lut->lut_slice = slice;
	lut->lut_reply_fail_id = reply_fail_id;
	lut->lut_request_fail_id = request_fail_id;

	/* sptlrcp variables init */
	rwlock_init(&lut->lut_sptlrpc_lock);
	sptlrpc_rule_set_init(&lut->lut_sptlrpc_rset);
	lut->lut_mds_capa = 1;
	lut->lut_oss_capa = 1;

	spin_lock_init(&lut->lut_flags_lock);
	lut->lut_sync_lock_cancel = NEVER_SYNC_ON_CANCEL;

	/* last_rcvd initialization is needed by replayable targets only */
	if (!obd->obd_replayable)
		RETURN(0);

	spin_lock_init(&lut->lut_translock);

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
		GOTO(out_bitmap, rc);
	}

	lut->lut_last_rcvd = o;
	rc = tgt_server_data_init(env, lut);
	if (rc < 0)
		GOTO(out_obj, rc);

	/* prepare transactions callbacks */
	lut->lut_txn_cb.dtc_txn_start = tgt_txn_start_cb;
	lut->lut_txn_cb.dtc_txn_stop = tgt_txn_stop_cb;
	lut->lut_txn_cb.dtc_txn_commit = NULL;
	lut->lut_txn_cb.dtc_cookie = lut;
	lut->lut_txn_cb.dtc_tag = LCT_DT_THREAD | LCT_MD_THREAD;
	CFS_INIT_LIST_HEAD(&lut->lut_txn_cb.dtc_linkage);

	dt_txn_callback_add(lut->lut_bottom, &lut->lut_txn_cb);

	RETURN(0);
out_obj:
	lu_object_put(env, &lut->lut_last_rcvd->do_lu);
	lut->lut_last_rcvd = NULL;
out_bitmap:
	OBD_FREE(lut->lut_client_bitmap, LR_MAX_CLIENTS >> 3);
	lut->lut_client_bitmap = NULL;
	return rc;
}
EXPORT_SYMBOL(tgt_init);

void tgt_fini(const struct lu_env *env, struct lu_target *lut)
{
	ENTRY;

	sptlrpc_rule_set_free(&lut->lut_sptlrpc_rset);

	if (lut->lut_client_bitmap) {
		OBD_FREE(lut->lut_client_bitmap, LR_MAX_CLIENTS >> 3);
		lut->lut_client_bitmap = NULL;
	}
	if (lut->lut_last_rcvd) {
		dt_txn_callback_del(lut->lut_bottom, &lut->lut_txn_cb);
		lu_object_put(env, &lut->lut_last_rcvd->do_lu);
		lut->lut_last_rcvd = NULL;
	}
	EXIT;
}
EXPORT_SYMBOL(tgt_fini);

/* context key constructor/destructor: tg_key_init, tg_key_fini */
LU_KEY_INIT_FINI(tgt, struct tgt_thread_info);
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
EXPORT_SYMBOL(tgt_thread_key);

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

	tgt_page_to_corrupt = alloc_page(GFP_IOFS);

	tgt_key_init_generic(&tgt_thread_key, NULL);
	lu_context_key_register_many(&tgt_thread_key, NULL);

	tgt_ses_key_init_generic(&tgt_session_key, NULL);
	lu_context_key_register_many(&tgt_session_key, NULL);

	RETURN(0);
}

void tgt_mod_exit(void)
{
	if (tgt_page_to_corrupt != NULL)
		page_cache_release(tgt_page_to_corrupt);

	lu_context_key_degister(&tgt_thread_key);
	lu_context_key_degister(&tgt_session_key);
}

