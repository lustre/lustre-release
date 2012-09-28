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
 */

#include "lquota_internal.h"

#ifndef _QMT_INTERNAL_H
#define _QMT_INTERNAL_H

/*
 * The Quota Master Target Device.
 * The qmt is responsible for:
 * - all interactions with MDT0 (provide request handlers, share ldlm namespace,
 *   manage ldlm lvbo, ...)
 * - all quota lock management (i.e. global quota locks as well as per-ID locks)
 * - manage the quota pool configuration
 *
 * That's the structure MDT0 connects to in mdt_quota_init().
 */
struct qmt_device {
	/* Super-class. dt_device/lu_device for this master target */
	struct dt_device	qmt_dt_dev;

	/* service name of this qmt */
	char			qmt_svname[MAX_OBD_NAME];

	/* Reference to the next device in the side stack
	 * The child device is actually the OSD device where we store the quota
	 * index files */
	struct obd_export	*qmt_child_exp;
	struct dt_device	*qmt_child;
};

/* Common data shared by qmt handlers */
struct qmt_thread_info {
	union lquota_rec	qti_rec;
	union lquota_id		qti_id;
};

extern struct lu_context_key qmt_thread_key;

/* helper function to extract qmt_thread_info from current environment */
static inline
struct qmt_thread_info *qmt_info(const struct lu_env *env)
{
	struct qmt_thread_info	*info;

	info = lu_context_key_get(&env->le_ctx, &qmt_thread_key);
	if (info == NULL) {
		lu_env_refill((struct lu_env *)env);
		info = lu_context_key_get(&env->le_ctx, &qmt_thread_key);
	}
	LASSERT(info);
	return info;
}

/* helper routine to convert a lu_device into a qmt_device */
static inline struct qmt_device *lu2qmt_dev(struct lu_device *ld)
{
	return container_of0(lu2dt_dev(ld), struct qmt_device, qmt_dt_dev);
}

/* helper routine to convert a qmt_device into lu_device */
static inline struct lu_device *qmt2lu_dev(struct qmt_device *qmt)
{
	return &qmt->qmt_dt_dev.dd_lu_dev;
}

/* qmt_lock.c */
int qmt_intent_policy(const struct lu_env *, struct lu_device *,
		      struct ptlrpc_request *, struct ldlm_lock **, int);
int qmt_lvbo_init(struct lu_device *, struct ldlm_resource *);
int qmt_lvbo_update(struct lu_device *, struct ldlm_resource *,
		    struct ptlrpc_request *, int);
int qmt_lvbo_size(struct lu_device *, struct ldlm_lock *);
int qmt_lvbo_fill(struct lu_device *, struct ldlm_lock *, void *, int);
int qmt_lvbo_free(struct lu_device *, struct ldlm_resource *);
#endif /* _QMT_INTERNAL_H */
