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
 * Copyright (c) 2012 Intel, Inc.
 * Use is subject to license terms.
 *
 * Author: Johann Lombardi <johann.lombardi@intel.com>
 * Author: Niu    Yawei    <yawei.niu@intel.com>
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif

#define DEBUG_SUBSYSTEM S_LQUOTA

#include <lustre_dlm.h>
#include "qmt_internal.h"

/* intent policy function called from mdt_intent_opc() when the intent is of
 * quota type */
int qmt_intent_policy(const struct lu_env *env, struct lu_device *ld,
		      struct ptlrpc_request *req, struct ldlm_lock **lockp,
		      int flags)
{
	ENTRY;

	req_capsule_extend(&req->rq_pill, &RQF_LDLM_INTENT_QUOTA);
	RETURN(ELDLM_LOCK_ABORTED);
}

/*
 * Initialize quota LVB associated with quota indexes.
 * Called with res->lr_lvb_sem held
 */
int qmt_lvbo_init(struct lu_device *ld, struct ldlm_resource *res)
{
	return 0;
}

/*
 * Update LVB associated with the global quota index.
 * This function is called from the DLM itself after a glimpse callback, in this
 * case valid ptlrpc request is passed. It is also called directly from the
 * quota master in order to refresh the global index version after a quota limit
 * change.
 */
int qmt_lvbo_update(struct lu_device *ld, struct ldlm_resource *res,
		    struct ptlrpc_request *req, int increase_only)
{
	return 0;
}

/*
 * Report size of lvb to ldlm layer in order to allocate lvb buffer
 */
int qmt_lvbo_size(struct lu_device *ld, struct ldlm_lock *lock)
{
	return 0;
}

/*
 * Fill request buffer with lvb
 */
int qmt_lvbo_fill(struct lu_device *ld, struct ldlm_lock *lock, void *lvb,
		  int lvblen)
{
	return 0;
}

/*
 * Free lvb associated with a given ldlm resource
 */
int qmt_lvbo_free(struct lu_device *ld, struct ldlm_resource *res)
{
	return 0;
}
