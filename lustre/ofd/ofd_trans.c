// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2014, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * This file provides functions for OBD Filter Device (OFD) transaction
 * management.
 *
 * Author: Alex Zhuravlev <alexey.zhuravlev@intel.com>
 * Author: Mikhail Pershin <mike.pershin@intel.com>
 */

#define DEBUG_SUBSYSTEM S_FILTER

#include "ofd_internal.h"

/**
 * Create new transaction in OFD.
 *
 * This function creates a transaction with dt_trans_create()
 * and makes it synchronous if required by the export state.
 *
 * \param[in] env	execution environment
 * \param[in] ofd	OFD device
 *
 * \retval		struct thandle if transaction was created successfully
 * \retval		ERR_PTR on negative value in case of error
 */
struct thandle *ofd_trans_create(const struct lu_env *env,
				 struct ofd_device *ofd)
{
	struct ofd_thread_info	*info = ofd_info(env);
	struct thandle		*th;

	LASSERT(info);

	if (unlikely(ofd->ofd_readonly)) {
		CERROR("%s: Deny transaction for read-only OFD device\n",
		       ofd_name(ofd));
		return ERR_PTR(-EROFS);
	}

	th = dt_trans_create(env, ofd->ofd_osd);
	if (IS_ERR(th))
		return th;

	/* export can require sync operations */
	if (info->fti_exp != NULL)
		th->th_sync |= info->fti_exp->exp_need_sync;
	return th;
}

/**
 * Start transaction in OFD.
 *
 * This function updates the given \a obj object version and calls
 * dt_trans_start().
 *
 * \param[in] env	execution environment
 * \param[in] ofd	OFD device
 * \param[in] obj	OFD object affected by this transaction
 * \param[in] th	transaction handle
 *
 * \retval		0 if successful
 * \retval		negative value in case of error
 */
int ofd_trans_start(const struct lu_env *env, struct ofd_device *ofd,
		    struct ofd_object *obj, struct thandle *th)
{
	/* version change is required for this object */
	if (obj != NULL)
		tgt_vbr_obj_set(env, ofd_object_child(obj));

	return dt_trans_start(env, ofd->ofd_osd, th);
}

/**
 * Stop transaction in OFD.
 *
 * This function fills thandle::th_result with result of whole operation
 * and calls dt_trans_stop().
 *
 * \param[in] env	execution environment
 * \param[in] ofd	OFD device
 * \param[in] th	transaction handle
 * \param[in] rc	result code of whole operation
 *
 * \retval		0 if successful
 * \retval		negative value if case of error
 */
int ofd_trans_stop(const struct lu_env *env, struct ofd_device *ofd,
		    struct thandle *th, int rc)
{
	th->th_result = rc;
	return dt_trans_stop(env, ofd->ofd_osd, th);
}
