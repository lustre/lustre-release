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

	if (env->le_ses == NULL || info->fti_exp == NULL)
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

/* Update last_rcvd records with the latest transaction data */
int ofd_txn_stop_cb(const struct lu_env *env, struct thandle *txn,
		    void *cookie)
{
	struct ofd_device	*ofd = cookie;
	struct ofd_thread_info	*info = ofd_info(env);
	struct dt_object	*obj;
	struct tgt_session_info	*tsi;
	bool			 echo_client;
	int			 rc;

	ENTRY;

	if (env->le_ses == NULL || info->fti_exp == NULL)
		RETURN(0);

	tsi = tgt_ses_info(env);

	echo_client = (tgt_ses_req(tsi) == NULL);

	if (info->fti_has_trans && !echo_client) {
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

	/** VBR: set new versions */
	if (info->fti_obj != NULL)
		obj = ofd_object_child(info->fti_obj);
	else
		obj = NULL;

	if (unlikely(echo_client)) /* echo client special case */
		rc = tgt_last_rcvd_update_echo(env, &ofd->ofd_lut, obj, txn,
					       tsi->tsi_exp);
	else
		rc = tgt_last_rcvd_update(env, &ofd->ofd_lut, obj, 0, txn,
					  tgt_ses_req(tsi));
	RETURN(rc);
}

