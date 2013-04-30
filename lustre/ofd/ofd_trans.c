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
 * Copyright (c) 2012, 2013, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/ofd/ofd_recovery.c
 *
 * Author: Alex Zhuravlev <bzzz@whamcloud.com>
 * Author: Mikhail Pershin <tappro@whamcloud.com>
 */

#define DEBUG_SUBSYSTEM S_FILTER

#include "ofd_internal.h"

struct thandle *ofd_trans_create(const struct lu_env *env,
				 struct ofd_device *ofd)
{
	struct ofd_thread_info	*info = ofd_info(env);
	struct thandle		*th;

	LASSERT(info);

	th = dt_trans_create(env, ofd->ofd_osd);
	if (IS_ERR(th))
		return th;

	/* export can require sync operations */
	if (info->fti_exp != NULL)
		th->th_sync |= info->fti_exp->exp_need_sync;
	return th;
}

int ofd_trans_start(const struct lu_env *env, struct ofd_device *ofd,
		    struct ofd_object *obj, struct thandle *th)
{
	struct ofd_thread_info	*info = ofd_info(env);
	int			 rc;

	if (info->fti_exp == NULL)
		return 0;

	/* declare last_rcvd update */
	rc = dt_declare_record_write(env, ofd->ofd_lut.lut_last_rcvd,
				     sizeof(struct lsd_client_data),
				     info->fti_exp->exp_target_data.ted_lr_off,
				     th);
	if (rc)
		RETURN(rc);

	/* declare last_rcvd header update */
	rc = dt_declare_record_write(env, ofd->ofd_lut.lut_last_rcvd,
				     sizeof(ofd->ofd_lut.lut_lsd), 0, th);
	if (rc)
		RETURN(rc);

	/* version change is required for this object */
	if (obj) {
		ofd_info(env)->fti_obj = obj;
		rc = dt_declare_version_set(env, ofd_object_child(obj), th);
		if (rc)
			RETURN(rc);
	}

	return dt_trans_start(env, ofd->ofd_osd, th);
}

void ofd_trans_stop(const struct lu_env *env, struct ofd_device *ofd,
		    struct thandle *th, int rc)
{
	th->th_result = rc;
	dt_trans_stop(env, ofd->ofd_osd, th);
}

/*
 * last_rcvd & last_committed update callbacks
 */
static int ofd_last_rcvd_update(struct ofd_thread_info *info,
				struct thandle *th)
{
	struct ofd_device		*ofd = ofd_exp(info->fti_exp);
	struct filter_export_data	*fed;
	struct lsd_client_data		*lcd;
	__s32				 rc = th->th_result;
	__u64				*transno_p;
	loff_t				 off;
	int				 err;
	bool				 lw_client = false;

	ENTRY;

	LASSERT(ofd);
	LASSERT(info->fti_exp);

	if (exp_connect_flags(info->fti_exp) & OBD_CONNECT_LIGHTWEIGHT)
		lw_client = true;

	fed = &info->fti_exp->exp_filter_data;
	LASSERT(fed);
	lcd = fed->fed_ted.ted_lcd;
	/* if the export has already been disconnected, we have no last_rcvd
	 * slot, update server data with latest transno then */
	if (lcd == NULL) {
		CWARN("commit transaction for disconnected client %s: rc %d\n",
		      info->fti_exp->exp_client_uuid.uuid, rc);
		err = tgt_server_data_write(info->fti_env, &ofd->ofd_lut, th);
		RETURN(err);
	}
	/* ofd connect may cause transaction before export has last_rcvd
	 * slot */
	if (fed->fed_ted.ted_lr_idx < 0 && !lw_client)
		RETURN(0);
	off = fed->fed_ted.ted_lr_off;

	transno_p = &lcd->lcd_last_transno;
	lcd->lcd_last_xid = info->fti_xid;

	/*
	 * When we store zero transno in mcd we can lost last transno value
	 * because mcd contains 0, but msd is not yet written
	 * The server data should be updated also if the latest
	 * transno is rewritten by zero. See the bug 11125 for details.
	 */
	if (info->fti_transno == 0 &&
	    *transno_p == ofd->ofd_lut.lut_last_transno) {
		spin_lock(&ofd->ofd_lut.lut_translock);
		ofd->ofd_lut.lut_lsd.lsd_last_transno =
						ofd->ofd_lut.lut_last_transno;
		spin_unlock(&ofd->ofd_lut.lut_translock);
		tgt_server_data_write(info->fti_env, &ofd->ofd_lut, th);
	}

	*transno_p = info->fti_transno;
	if (lw_client) {
		/* Although lightweight (LW) connections have no slot in
		 * last_rcvd, we still want to maintain the in-memory
		 * lsd_client_data structure in order to properly handle reply
		 * reconstruction. */
		struct lu_target        *tg =&ofd->ofd_lut;
		bool                     update = false;

		err = 0;
		/* All operations performed by LW clients are synchronous and
		 * we store the committed transno in the last_rcvd header */
		spin_lock(&tg->lut_translock);
		if (info->fti_transno > tg->lut_lsd.lsd_last_transno) {
			tg->lut_lsd.lsd_last_transno = info->fti_transno;
			update = true;
		}
		spin_unlock(&tg->lut_translock);
		if (update)
			err = tgt_server_data_write(info->fti_env, tg, th);
	} else {
		LASSERT(fed->fed_ted.ted_lr_off > 0);
		err = tgt_client_data_write(info->fti_env, &ofd->ofd_lut, lcd,
				    &off, th);
	}

	RETURN(err);
}

/* Update last_rcvd records with the latest transaction data */
int ofd_txn_stop_cb(const struct lu_env *env, struct thandle *txn,
		    void *cookie)
{
	struct ofd_device *ofd = cookie;
	struct ofd_thread_info *info;

	ENTRY;

	info = lu_context_key_get(&env->le_ctx, &ofd_thread_key);

	if (info->fti_exp == NULL)
		 RETURN(0);

	LASSERT(ofd_exp(info->fti_exp) == ofd);
	if (info->fti_has_trans) {
		if (info->fti_mult_trans == 0) {
			CERROR("More than one transaction "LPU64"\n",
			       info->fti_transno);
			RETURN(0);
		}
		/* we need another transno to be assigned */
		info->fti_transno = 0;
	} else if (txn->th_result == 0) {
		info->fti_has_trans = 1;
	}

	spin_lock(&ofd->ofd_lut.lut_translock);
	if (txn->th_result != 0) {
		if (info->fti_transno != 0) {
			CERROR("Replay transno "LPU64" failed: rc %d\n",
			       info->fti_transno, txn->th_result);
			info->fti_transno = 0;
		}
	} else if (info->fti_transno == 0) {
		info->fti_transno = ++ofd->ofd_lut.lut_last_transno;
	} else {
		/* should be replay */
		if (info->fti_transno > ofd->ofd_lut.lut_last_transno)
			ofd->ofd_lut.lut_last_transno = info->fti_transno;
	}
	spin_unlock(&ofd->ofd_lut.lut_translock);

	/** VBR: set new versions */
	if (txn->th_result == 0 && info->fti_obj != NULL) {
		dt_version_set(env, ofd_object_child(info->fti_obj),
			       info->fti_transno, txn);
		info->fti_obj = NULL;
	}

	/* filling reply data */
	CDEBUG(D_INODE, "transno = %llu, last_committed = %llu\n",
	       info->fti_transno, ofd_obd(ofd)->obd_last_committed);

	/* if can't add callback, do sync write */
	txn->th_sync |= !!tgt_last_commit_cb_add(txn, &ofd->ofd_lut,
						 info->fti_exp,
						 info->fti_transno);

	return ofd_last_rcvd_update(info, txn);
}

