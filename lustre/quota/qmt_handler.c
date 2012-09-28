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

#include <obd_class.h>
#include "qmt_internal.h"

/*
 * Handle quotactl request.
 *
 * \param env   - is the environment passed by the caller
 * \param ld    - is the lu device associated with the qmt
 * \param oqctl - is the quotactl request
 */
static int qmt_quotactl(const struct lu_env *env, struct lu_device *ld,
			struct obd_quotactl *oqctl)
{
	struct qmt_device	*qmt = lu2qmt_dev(ld);
	int			 rc = 0;
	ENTRY;

	LASSERT(qmt != NULL);

	if (oqctl->qc_type >= MAXQUOTAS)
		/* invalid quota type */
		RETURN(-EINVAL);

	switch (oqctl->qc_cmd) {

	case Q_GETINFO:
	case Q_SETINFO:
	case Q_SETQUOTA:
		/* XXX: not implemented yet. */
		CERROR("quotactl operation %d not implemented yet\n",
		       oqctl->qc_cmd);
		RETURN(-EOPNOTSUPP);

	case Q_GETQUOTA:
		/* XXX: return no limit for now, just for testing purpose */
		memset(&oqctl->qc_dqblk, 0, sizeof(struct obd_dqblk));
		oqctl->qc_dqblk.dqb_valid = QIF_LIMITS;
		rc = 0;
		break;

	default:
		CERROR("%s: unsupported quotactl command: %d\n",
		       qmt->qmt_svname, oqctl->qc_cmd);
		RETURN(-EFAULT);
	}

	RETURN(rc);
}

/*
 * Handle quota request from slave.
 *
 * \param env  - is the environment passed by the caller
 * \param ld   - is the lu device associated with the qmt
 * \param req  - is the quota acquire request
 */
static int qmt_dqacq(const struct lu_env *env, struct lu_device *ld,
		     struct ptlrpc_request *req)
{
	struct quota_body	*qbody, *repbody;
	ENTRY;

	qbody = req_capsule_client_get(&req->rq_pill, &RMF_QUOTA_BODY);
	if (qbody == NULL)
		RETURN(err_serious(-EPROTO));

	repbody = req_capsule_server_get(&req->rq_pill, &RMF_QUOTA_BODY);
	if (repbody == NULL)
		RETURN(err_serious(-EFAULT));

	RETURN(0);
}

/* Vector of quota request handlers. This vector is used by the MDT to forward
 * requests to the quota master. */
struct qmt_handlers qmt_hdls = {
	/* quota request handlers */
	.qmth_quotactl		= qmt_quotactl,
	.qmth_dqacq		= qmt_dqacq,

	/* ldlm handlers */
	.qmth_intent_policy	= qmt_intent_policy,
	.qmth_lvbo_init		= qmt_lvbo_init,
	.qmth_lvbo_update	= qmt_lvbo_update,
	.qmth_lvbo_size		= qmt_lvbo_size,
	.qmth_lvbo_fill		= qmt_lvbo_fill,
	.qmth_lvbo_free		= qmt_lvbo_free,
};
EXPORT_SYMBOL(qmt_hdls);
