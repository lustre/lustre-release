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
 * Copyright (c) 2012, Intel Corporation.
 * Use is subject to license terms.
 *
 * lustre/mdt/mdt_lvb.c
 *
 * Author: Jinshan Xiong <jinshan.xiong@intel.com>
 */

#define DEBUG_SUBSYSTEM S_MDS

#include "mdt_internal.h"

/* Called with res->lr_lvb_sem held */
static int mdt_lvbo_init(struct ldlm_resource *res)
{
	if (IS_LQUOTA_RES(res)) {
		struct mdt_device	*mdt;

		mdt = ldlm_res_to_ns(res)->ns_lvbp;
		if (mdt->mdt_qmt_dev == NULL)
			return 0;

		/* call lvbo init function of quota master */
		return qmt_hdls.qmth_lvbo_init(mdt->mdt_qmt_dev, res);
	}

	return 0;
}

static int mdt_lvbo_update(struct ldlm_resource *res,
			   struct ptlrpc_request *req,
			   int increase_only)
{
	if (IS_LQUOTA_RES(res)) {
		struct mdt_device	*mdt;

		mdt = ldlm_res_to_ns(res)->ns_lvbp;
		if (mdt->mdt_qmt_dev == NULL)
			return 0;

		/* call lvbo update function of quota master */
		return qmt_hdls.qmth_lvbo_update(mdt->mdt_qmt_dev, res, req,
						 increase_only);
	}

	return 0;
}


static int mdt_lvbo_size(struct ldlm_lock *lock)
{
	if (IS_LQUOTA_RES(lock->l_resource)) {
		struct mdt_device	*mdt;

		mdt = ldlm_res_to_ns(lock->l_resource)->ns_lvbp;
		if (mdt->mdt_qmt_dev == NULL)
			return 0;

		/* call lvbo size function of quota master */
		return qmt_hdls.qmth_lvbo_size(mdt->mdt_qmt_dev, lock);
	}

	return 0;
}

static int mdt_lvbo_fill(struct ldlm_lock *lock, void *lvb, int lvblen)
{
	if (IS_LQUOTA_RES(lock->l_resource)) {
		struct mdt_device	*mdt;

		mdt = ldlm_res_to_ns(lock->l_resource)->ns_lvbp;
		if (mdt->mdt_qmt_dev == NULL)
			return 0;

		/* call lvbo fill function of quota master */
		return qmt_hdls.qmth_lvbo_fill(mdt->mdt_qmt_dev, lock, lvb,
					       lvblen);
	}

	return 0;
}

static int mdt_lvbo_free(struct ldlm_resource *res)
{
	if (IS_LQUOTA_RES(res)) {
		struct mdt_device	*mdt;

		mdt = ldlm_res_to_ns(res)->ns_lvbp;
		if (mdt->mdt_qmt_dev == NULL)
			return 0;

		/* call lvbo free function of quota master */
		return qmt_hdls.qmth_lvbo_free(mdt->mdt_qmt_dev, res);
	}

	return 0;
}

struct ldlm_valblock_ops mdt_lvbo = {
	lvbo_init:	mdt_lvbo_init,
	lvbo_update:	mdt_lvbo_update,
	lvbo_size:	mdt_lvbo_size,
	lvbo_fill:	mdt_lvbo_fill,
	lvbo_free:	mdt_lvbo_free
};
