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
 * Author: Johann Lombardi <johann@whamcloud.com>
 * Author: Niu    Yawei    <niu@whamcloud.com>
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif

#define DEBUG_SUBSYSTEM S_LQUOTA

#include "lquota_internal.h"

static struct dt_object_format dt_acct_format = {
	.dof_type		= DFT_INDEX,
	.u.dof_idx.di_feat	= &dt_acct_features
};

/**
 * Look-up accounting object to collect space usage information for user
 * or group.
 *
 * \param env - is the environment passed by the caller
 * \param dev - is the dt_device storing the accounting object
 * \param oid - is the object id of the accounting object to initialize, must be
 *              either ACCT_USER_OID or ACCT_GROUP_OID.
 */
struct dt_object *acct_obj_lookup(const struct lu_env *env,
				  struct dt_device *dev, __u32 oid)
{
	struct dt_object	*obj = NULL;
	struct lu_fid		 fid;
	struct lu_attr		 attr;
	int			 rc;
	ENTRY;

	memset(&attr, 0, sizeof(attr));
	attr.la_valid = LA_MODE;
	attr.la_mode = S_IFREG | S_IRUGO | S_IWUSR;
	lu_local_obj_fid(&fid, oid);

	/* lookup/create the accounting object */
	obj = dt_find_or_create(env, dev, &fid, &dt_acct_format, &attr);
	if (IS_ERR(obj))
		RETURN(obj);

	if (obj->do_index_ops == NULL) {
		/* set up indexing operations */
		rc = obj->do_ops->do_index_try(env, obj, &dt_acct_features);
		if (rc) {
			lu_object_put(env, &obj->do_lu);
			RETURN(ERR_PTR(rc));
		}
	}
	RETURN(obj);
}

/*
 * Helper routine to retrieve slave information.
 * This function converts a quotactl request into quota/accounting object
 * operations. It is independant of the slave stack which is only accessible
 * from the OSD layer.
 *
 * \param env   - is the environment passed by the caller
 * \param dev   - is the dt_device this quotactl is executed on
 * \param oqctl - is the quotactl request
 */
int lquotactl_slv(const struct lu_env *env, struct dt_device *dev,
		  struct obd_quotactl *oqctl)
{
	struct acct_rec		 rec;
	__u64			 key;
	struct dt_object	*obj;
	int			 rc = 0;
	ENTRY;

	if (oqctl->qc_cmd != Q_GETOQUOTA) {
		/* as in many other places, dev->dd_lu_dev.ld_obd->obd_name
		 * point to a valid obd_name, to be fixed in LU-1574 */
		CERROR("%s: Unsupported quotactl command: %x\n",
		       dev->dd_lu_dev.ld_obd->obd_name, oqctl->qc_cmd);
		RETURN(-EOPNOTSUPP);
	}

	if (oqctl->qc_type == USRQUOTA)
		obj = acct_obj_lookup(env, dev, ACCT_USER_OID);
	else if (oqctl->qc_type == GRPQUOTA)
		obj = acct_obj_lookup(env, dev, ACCT_GROUP_OID);
	else
		/* no support for directory quota yet */
		RETURN(-EOPNOTSUPP);

	if (IS_ERR(obj))
		RETURN(-EOPNOTSUPP);
	if (obj->do_index_ops == NULL)
		GOTO(out, rc = -EINVAL);

	/* qc_id is a 32-bit field while a key has 64 bits */
	key = oqctl->qc_id;

	/* lookup record storing space accounting information for this ID */
	rc = dt_lookup(env, obj, (struct dt_rec *)&rec, (struct dt_key *)&key,
		       BYPASS_CAPA);
	if (rc < 0)
		GOTO(out, rc);

	memset(&oqctl->qc_dqblk, 0, sizeof(struct obd_dqblk));
	oqctl->qc_dqblk.dqb_curspace  = rec.bspace;
	oqctl->qc_dqblk.dqb_curinodes = rec.ispace;
	oqctl->qc_dqblk.dqb_valid     = QIF_USAGE;
	/* TODO: must set {hard,soft}limit and grace time */

	EXIT;
out:
	lu_object_put(env, &obj->do_lu);
        return rc;
}
EXPORT_SYMBOL(lquotactl_slv);
