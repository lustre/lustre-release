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
 * Copyright (c) 2012, 2015, Intel Corporation.
 * Use is subject to license terms.
 *
 * Author: Johann Lombardi <johann.lombardi@intel.com>
 * Author: Niu    Yawei    <yawei.niu@intel.com>
 */

#define DEBUG_SUBSYSTEM S_LQUOTA

#include <linux/version.h>
#include <linux/module.h>
#include <linux/init.h>

#include "lquota_internal.h"

struct kmem_cache *lqe_kmem;

struct lu_kmem_descr lquota_caches[] = {
	{
		.ckd_cache = &lqe_kmem,
		.ckd_name  = "lqe_kmem",
		.ckd_size  = sizeof(struct lquota_entry)
	},
	{
		.ckd_cache = NULL
	}
};

/* register lquota key */
LU_KEY_INIT_FINI(lquota, struct lquota_thread_info);
LU_CONTEXT_KEY_DEFINE(lquota, LCT_MD_THREAD | LCT_DT_THREAD | LCT_LOCAL);
LU_KEY_INIT_GENERIC(lquota);

static inline __u32 qtype2acct_oid(int qtype)
{
	switch (qtype) {
	case USRQUOTA:
		return ACCT_USER_OID;
	case GRPQUOTA:
		return ACCT_GROUP_OID;
	case PRJQUOTA:
		return ACCT_PROJECT_OID;
	}

	return ACCT_GROUP_OID;
}

/**
 * Look-up accounting object to collect space usage information for user
 * or group.
 *
 * \param env  - is the environment passed by the caller
 * \param dev  - is the dt_device storing the accounting object
 * \param type - is the quota type, either USRQUOTA or GRPQUOTA
 */
struct dt_object *acct_obj_lookup(const struct lu_env *env,
				  struct dt_device *dev, int type)
{
	struct lquota_thread_info	*qti = lquota_info(env);
	struct dt_object		*obj = NULL;
	ENTRY;

	lu_local_obj_fid(&qti->qti_fid, qtype2acct_oid(type));

	/* lookup the accounting object */
	obj = dt_locate(env, dev, &qti->qti_fid);
	if (IS_ERR(obj))
		RETURN(obj);

	if (!dt_object_exists(obj)) {
		dt_object_put(env, obj);
		RETURN(ERR_PTR(-ENOENT));
	}

	if (obj->do_index_ops == NULL) {
		int rc;

		/* set up indexing operations */
		rc = obj->do_ops->do_index_try(env, obj, &dt_acct_features);
		if (rc) {
			CERROR("%s: failed to set up indexing operations for %s"
			       " acct object rc:%d\n",
			       dev->dd_lu_dev.ld_obd->obd_name,
			       qtype_name(type), rc);
			dt_object_put(env, obj);
			RETURN(ERR_PTR(rc));
		}
	}
	RETURN(obj);
}

/**
 * Initialize slave index object to collect local quota limit for user or group.
 *
 * \param env - is the environment passed by the caller
 * \param dev - is the dt_device storing the slave index object
 * \param type - is the quota type, either USRQUOTA or GRPQUOTA
 */
static struct dt_object *quota_obj_lookup(const struct lu_env *env,
					  struct dt_device *dev, int type)
{
	struct lquota_thread_info	*qti = lquota_info(env);
	struct dt_object		*obj = NULL;
	ENTRY;

	qti->qti_fid.f_seq = FID_SEQ_QUOTA;
	qti->qti_fid.f_oid = qtype2slv_oid(type);
	qti->qti_fid.f_ver = 0;

	/* lookup the quota object */
	obj = dt_locate(env, dev, &qti->qti_fid);
	if (IS_ERR(obj))
		RETURN(obj);

	if (!dt_object_exists(obj)) {
		dt_object_put(env, obj);
		RETURN(ERR_PTR(-ENOENT));
	}

	if (obj->do_index_ops == NULL) {
		int rc;

		/* set up indexing operations */
		rc = obj->do_ops->do_index_try(env, obj,
					       &dt_quota_slv_features);
		if (rc) {
			CERROR("%s: failed to set up indexing operations for %s"
			       " slave index object rc:%d\n",
			       dev->dd_lu_dev.ld_obd->obd_name,
			       qtype_name(type), rc);
			dt_object_put(env, obj);
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
	struct lquota_thread_info	*qti = lquota_info(env);
	__u64				 key;
	struct dt_object		*obj;
	struct obd_dqblk		*dqblk = &oqctl->qc_dqblk;
	int				 rc;
	ENTRY;

	if (oqctl->qc_cmd != Q_GETOQUOTA) {
		/* as in many other places, dev->dd_lu_dev.ld_obd->obd_name
		 * point to an invalid obd_name, to be fixed in LU-1574 */
		CERROR("%s: Unsupported quotactl command: %x\n",
		       dev->dd_lu_dev.ld_obd->obd_name, oqctl->qc_cmd);
		RETURN(-EOPNOTSUPP);
	}

	if (oqctl->qc_type < 0 || oqctl->qc_type >= LL_MAXQUOTAS)
		RETURN(-EOPNOTSUPP);

	/* qc_id is a 32-bit field while a key has 64 bits */
	key = oqctl->qc_id;

	/* Step 1: collect accounting information */

	obj = acct_obj_lookup(env, dev, oqctl->qc_type);
	if (IS_ERR(obj))
		RETURN(-EOPNOTSUPP);
	if (obj->do_index_ops == NULL)
		GOTO(out, rc = -EINVAL);

	/* lookup record storing space accounting information for this ID */
	rc = dt_lookup(env, obj, (struct dt_rec *)&qti->qti_acct_rec,
		       (struct dt_key *)&key);
	if (rc < 0)
		GOTO(out, rc);

	memset(&oqctl->qc_dqblk, 0, sizeof(struct obd_dqblk));
	dqblk->dqb_curspace	= qti->qti_acct_rec.bspace;
	dqblk->dqb_curinodes	= qti->qti_acct_rec.ispace;
	dqblk->dqb_valid	= QIF_USAGE;

	dt_object_put(env, obj);

	/* Step 2: collect enforcement information */

	obj = quota_obj_lookup(env, dev, oqctl->qc_type);
	if (IS_ERR(obj))
		RETURN(0);
	if (obj->do_index_ops == NULL)
		GOTO(out, rc = 0);

	memset(&qti->qti_slv_rec, 0, sizeof(qti->qti_slv_rec));
	/* lookup record storing enforcement information for this ID */
	rc = dt_lookup(env, obj, (struct dt_rec *)&qti->qti_slv_rec,
		       (struct dt_key *)&key);
	if (rc < 0 && rc != -ENOENT)
		GOTO(out, rc = 0);

	if (lu_device_is_md(dev->dd_lu_dev.ld_site->ls_top_dev)) {
		dqblk->dqb_ihardlimit = qti->qti_slv_rec.qsr_granted;
		dqblk->dqb_bhardlimit = 0;
	} else {
		dqblk->dqb_ihardlimit = 0;
		dqblk->dqb_bhardlimit = qti->qti_slv_rec.qsr_granted;
	}
	dqblk->dqb_valid |= QIF_LIMITS;

	GOTO(out, rc = 0);
out:
	dt_object_put(env, obj);
	return rc;
}
EXPORT_SYMBOL(lquotactl_slv);

static inline __u8 qtype2lqtype(int qtype)
{
	switch (qtype) {
	case USRQUOTA:
		return LQUOTA_TYPE_USR;
	case GRPQUOTA:
		return LQUOTA_TYPE_GRP;
	case PRJQUOTA:
		return LQUOTA_TYPE_PRJ;
	}

	return LQUOTA_TYPE_GRP;
}

static inline int lqtype2qtype(int lqtype)
{
	switch (lqtype) {
	case LQUOTA_TYPE_USR:
		return USRQUOTA;
	case LQUOTA_TYPE_GRP:
		return GRPQUOTA;
	case LQUOTA_TYPE_PRJ:
		return PRJQUOTA;
	}

	return GRPQUOTA;
}

/**
 * Helper routine returning the FID associated with the global index storing
 * quota settings for the storage pool \pool_id, resource type \pool_type and
 * the quota type \quota_type.
 */
void lquota_generate_fid(struct lu_fid *fid, int pool_id, int pool_type,
			int quota_type)
{
	__u8	 lqtype = qtype2lqtype(quota_type);

	fid->f_seq = FID_SEQ_QUOTA_GLB;
	fid->f_oid = (lqtype << 24) | (pool_type << 16) | (__u16)pool_id;
	fid->f_ver = 0;
}

/**
 * Helper routine used to extract pool ID, pool type and quota type from a
 * given FID.
 */
int lquota_extract_fid(const struct lu_fid *fid, int *pool_id, int *pool_type,
		       int *quota_type)
{
	unsigned int lqtype;
	ENTRY;

	if (fid->f_seq != FID_SEQ_QUOTA_GLB)
		RETURN(-EINVAL);

	if (pool_id != NULL) {
		lqtype = fid->f_oid & 0xffffU;
		if (lqtype != 0)
			/* we only support pool ID 0 for the time being */
			RETURN(-ENOTSUPP);
		*pool_id = lqtype;
	}

	if (pool_type != NULL) {
		lqtype = (fid->f_oid >> 16) & 0xffU;
		if (lqtype >= LQUOTA_LAST_RES)
			RETURN(-ENOTSUPP);

		*pool_type = lqtype;
	}

	if (quota_type != NULL) {
		lqtype = fid->f_oid >> 24;
		if (lqtype >= LQUOTA_TYPE_MAX)
			RETURN(-ENOTSUPP);

		*quota_type = lqtype2qtype(lqtype);
	}

	RETURN(0);
}

static int __init lquota_init(void)
{
	int	rc;
	ENTRY;

	lquota_key_init_generic(&lquota_thread_key, NULL);
	lu_context_key_register(&lquota_thread_key);

	rc = lu_kmem_init(lquota_caches);
	if (rc)
		GOTO(out_key, rc);

	rc = qmt_glb_init();
	if (rc)
		GOTO(out_caches, rc);

	rc = qsd_glb_init();
	if (rc)
		GOTO(out_qmt, rc);

	RETURN(0);

out_qmt:
	qmt_glb_fini();
out_caches:
	lu_kmem_fini(lquota_caches);
out_key:
	lu_context_key_degister(&lquota_thread_key);
	return rc;
}

static void __exit lquota_exit(void)
{
	qsd_glb_fini();
	qmt_glb_fini();
	lu_kmem_fini(lquota_caches);
	lu_context_key_degister(&lquota_thread_key);
}

MODULE_AUTHOR("OpenSFS, Inc. <http://www.lustre.org/>");
MODULE_DESCRIPTION("Lustre Quota");
MODULE_VERSION(LUSTRE_VERSION_STRING);
MODULE_LICENSE("GPL");

module_init(lquota_init);
module_exit(lquota_exit);
