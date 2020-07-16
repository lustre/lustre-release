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
 * Copyright (c) 2012, 2017, Intel Corporation.
 * Use is subject to license terms.
 *
 * Author: Johann Lombardi <johann.lombardi@intel.com>
 * Author: Niu    Yawei    <yawei.niu@intel.com>
 */

#define DEBUG_SUBSYSTEM S_LQUOTA

#include "qsd_internal.h"

/*
 * Initialize qsd-specific fields of quota entry.
 *
 * \param lqe - is the quota entry to initialize
 * \param arg - is the pointer to the qsd_qtype_info structure
 */
static void qsd_lqe_init(struct lquota_entry *lqe, void *arg)
{
	LASSERT(!lqe_is_master(lqe));

	/* initialize slave parameters */
	rwlock_init(&lqe->lqe_lock);
	memset(&lqe->lqe_lockh, 0, sizeof(lqe->lqe_lockh));
	lqe->lqe_pending_write = 0;
	lqe->lqe_pending_req   = 0;
	init_waitqueue_head(&lqe->lqe_waiters);
	lqe->lqe_usage    = 0;
	lqe->lqe_nopreacq = false;
}

/*
 * Update a slave quota entry. This is done by reading enforcement status from
 * the copy of the global index and then how much is the slave currenly owns
 * for this user from the slave index copy.
 *
 * \param env - the environment passed by the caller
 * \param lqe - is the quota entry to refresh
 * \param arg - is the pointer to the qsd_qtype_info structure
 * \param need_crt - needed to be compat with qmt_lqe_read
 */
static int qsd_lqe_read(const struct lu_env *env, struct lquota_entry *lqe,
			void *arg, bool need_crt)
{
	struct qsd_thread_info *qti = qsd_info(env);
	struct qsd_qtype_info  *qqi = (struct qsd_qtype_info *)arg;
	int			rc;

	LASSERT(!lqe_is_master(lqe));

	/* read record from global index copy to know whether quota is
	 * enforced for this user */
	rc = lquota_disk_read(env, qqi->qqi_glb_obj, &lqe->lqe_id,
			      (struct dt_rec *)&qti->qti_glb_rec);

	switch(rc) {
	case -ENOENT:
		/* no such entry, assume quota isn't enforced for this user */
		lqe->lqe_enforced = false;
		break;
	case 0:
		if (lqe->lqe_id.qid_uid == 0) {
			qqi->qqi_default_hardlimit =
						qti->qti_glb_rec.qbr_hardlimit;
			qqi->qqi_default_softlimit =
						qti->qti_glb_rec.qbr_softlimit;
			qqi->qqi_default_gracetime =
						qti->qti_glb_rec.qbr_granted;
		}

		if (lqe->lqe_id.qid_uid != 0 &&
		    (qti->qti_glb_rec.qbr_hardlimit != 0 ||
		     qti->qti_glb_rec.qbr_softlimit != 0))
			lqe->lqe_enforced = true;
		else
			lqe->lqe_enforced = false;
		break;
	default:
		LQUOTA_ERROR(lqe, "failed to read quota entry from global "
			     "index copy, rc:%d", rc);
		return rc;
	}

	if (lqe->lqe_id.qid_uid != 0 &&
	    (rc == -ENOENT ||
	     (LQUOTA_FLAG(qti->qti_glb_rec.qbr_time) & LQUOTA_FLAG_DEFAULT &&
	      qti->qti_glb_rec.qbr_hardlimit == 0 &&
	      qti->qti_glb_rec.qbr_softlimit == 0))) {
		struct lquota_entry *lqe_def;
		union lquota_id qid = { {0} };

		/* ensure the lqe storing the default quota setting loaded */
		lqe_def = lqe_locate(env, qqi->qqi_site, &qid);

		lqe->lqe_is_default = true;

		if (qqi->qqi_default_hardlimit != 0 ||
		    qqi->qqi_default_softlimit != 0) {
			LQUOTA_DEBUG(lqe, "enforced by default quota");
			lqe->lqe_enforced = true;
		}

		if (!IS_ERR(lqe_def))
			lqe_putref(lqe_def);
	}

	/* read record from slave index copy to find out how much space is
	 * currently owned by this slave */
	rc = lquota_disk_read(env, qqi->qqi_slv_obj, &lqe->lqe_id,
			      (struct dt_rec *)&qti->qti_slv_rec);
	switch(rc) {
	case -ENOENT:
		lqe->lqe_granted = 0;
		break;
	case 0:
		lqe->lqe_granted = qti->qti_slv_rec.qsr_granted;
		break;
	default:
		LQUOTA_ERROR(lqe, "failed to read quota entry from slave "
			     "index copy, rc:%d", rc);
		return rc;
	}

	/* don't know what the qunit value is yet */
	qsd_set_qunit(lqe, 0);

	/* read current disk-usage from disk */
	rc = qsd_refresh_usage(env, lqe);
	if (rc)
		return rc;

	LQUOTA_DEBUG(lqe, "successfully read from disk");
	return 0;
}

/*
 * Print lqe information for debugging.
 *
 * \param lqe - is the quota entry to debug
 * \param arg - is the pointer to the qsd_qtype_info structure
 * \param msgdata - debug message
 * \param fmt     - format of debug message
 */
static void qsd_lqe_debug(struct lquota_entry *lqe, void *arg,
			  struct libcfs_debug_msg_data *msgdata,
			  struct va_format *vaf)
{
	struct qsd_qtype_info	*qqi = (struct qsd_qtype_info *)arg;

	libcfs_debug_msg(msgdata,
			 "%pV qsd:%s qtype:%s id:%llu enforced:%d granted: %llu pending:%llu waiting:%llu req:%d usage: %llu qunit:%llu qtune:%llu edquot:%d default:%s\n",
			 vaf,
			 qqi->qqi_qsd->qsd_svname, qtype_name(qqi->qqi_qtype),
			 lqe->lqe_id.qid_uid, lqe->lqe_enforced,
			 lqe->lqe_granted, lqe->lqe_pending_write,
			 lqe->lqe_waiting_write, lqe->lqe_pending_req,
			 lqe->lqe_usage, lqe->lqe_qunit, lqe->lqe_qtune,
			 lqe->lqe_edquot, lqe->lqe_is_default ? "yes" : "no");
}

/*
 * Vector of quota entry operations supported on the slave
 */
const struct lquota_entry_operations qsd_lqe_ops = {
	.lqe_init		= qsd_lqe_init,
	.lqe_read		= qsd_lqe_read,
	.lqe_debug		= qsd_lqe_debug,
};

int qsd_write_version(const struct lu_env *env, struct qsd_qtype_info *qqi,
		      __u64 ver, bool global)
{
	struct qsd_instance *qsd = qqi->qqi_qsd;
	struct dt_object    *obj = global ? qqi->qqi_glb_obj :
					    qqi->qqi_slv_obj;
	int		     rc;
	ENTRY;

	rc = lquota_disk_update_ver(env, qsd->qsd_dev, obj, ver);
	if (rc)
		RETURN(rc);

	qsd_bump_version(qqi, ver, global);
	RETURN(0);
}

/*
 * Consult current disk space consumed by a given identifier.
 *
 * \param env   - the environment passed by the caller
 * \param qqi   - is the pointer to the qsd_qtype_info structure associated
 *                with the identifier.
 * \param lqe   - is the quota entry associated with the identifier
 */
int qsd_refresh_usage(const struct lu_env *env, struct lquota_entry *lqe)
{
	struct qsd_thread_info	*qti = qsd_info(env);
	struct lquota_acct_rec	*rec = &qti->qti_acct_rec;
	struct qsd_qtype_info	*qqi = lqe2qqi(lqe);
	int			 rc = 0;
	ENTRY;

	LASSERT(qqi->qqi_acct_obj);

	/* read disk usage */
	rc = lquota_disk_read(env, qqi->qqi_acct_obj, &lqe->lqe_id,
			      (struct dt_rec *)rec);
	switch(rc) {
	case -ENOENT:
		lqe->lqe_usage = 0;
		rc = 0;
		break;
	case 0:
		if (qqi->qqi_qsd->qsd_is_md)
			lqe->lqe_usage = rec->ispace;
		else
			lqe->lqe_usage = toqb(rec->bspace);
		break;
	default:
		LQUOTA_ERROR(lqe, "failed to read disk usage, rc:%d", rc);
		RETURN(rc);
	}

	LQUOTA_DEBUG(lqe, "disk usage: %llu", lqe->lqe_usage);
	RETURN(0);
}

/*
 * Update slave or global index copy.
 *
 * \param env    - the environment passed by the caller
 * \param qqi    - is the qsd_type_info structure managing the index to be
 *                 update
 * \param qid    - is the identifier for which we need to update the quota
 *                 settings
 * \param global - is set to true when updating the global index copy and to
 *                 false for the slave index copy.
 * \param ver    - is the new version of the index. If equal to 0, the version
 *                 of the index isn't changed
 * \param rec    - is the updated record to insert in the index file
 */
int qsd_update_index(const struct lu_env *env, struct qsd_qtype_info *qqi,
		     union lquota_id *qid, bool global, __u64 ver, void *rec)
{
	struct thandle		*th = NULL;
	struct dt_object	*obj;
	__u64			*new_verp = NULL;
	int			 flags = 0;
	int			 rc;
	ENTRY;

	obj = global ? qqi->qqi_glb_obj : qqi->qqi_slv_obj;

	/* allocate transaction */
	th = dt_trans_create(env, qqi->qqi_qsd->qsd_dev);
	if (IS_ERR(th))
		RETURN(PTR_ERR(th));

	/* reserve enough credits to update record in index file */
	rc = lquota_disk_declare_write(env, th, obj, qid);
	if (rc)
		GOTO(out, rc);

	/* start local transaction */
	rc = dt_trans_start_local(env, qqi->qqi_qsd->qsd_dev, th);
	if (rc)
		GOTO(out, rc);

	if (global) {
		/* Update record in global index copy */
		struct lquota_glb_rec *glb_rec = (struct lquota_glb_rec *)rec;

		CDEBUG(D_QUOTA, "%s: updating global index hardlimit: %llu, "
		       "softlimit: %llu for id %llu\n",
		       qqi->qqi_qsd->qsd_svname, glb_rec->qbr_hardlimit,
		       glb_rec->qbr_softlimit, qid->qid_uid);
	} else {
		/* Update record in slave index copy */
		struct lquota_slv_rec *slv_rec = (struct lquota_slv_rec *)rec;

		CDEBUG(D_QUOTA, "%s: update granted to %llu for id %llu"
		       "\n", qqi->qqi_qsd->qsd_svname, slv_rec->qsr_granted,
		       qid->qid_uid);
	}

	if (ver != 0) {
		new_verp = &ver;
		flags = LQUOTA_SET_VER;
	}

	/* write new record to index file */
	rc = lquota_disk_write(env, th, obj, qid, (struct dt_rec *)rec, flags,
			       new_verp);
	EXIT;
out:
	dt_trans_stop(env, qqi->qqi_qsd->qsd_dev, th);
	if (rc)
		CERROR("%s: failed to update %s index copy for id %llu, : rc = %d\n",
		       qqi->qqi_qsd->qsd_svname,
		       global ? "global" : "slave", qid->qid_uid, rc);
	else if (flags == LQUOTA_SET_VER)
		qsd_bump_version(qqi, ver, global);
	return rc;
}

/*
 * Update in-memory lquota entry with new quota setting from record \rec.
 * The record can either be a global record (i.e. lquota_glb_rec) or a slave
 * index record (i.e. lquota_slv_rec). In the former case, \global should be
 * set to true.
 *
 * \param env    - the environment passed by the caller
 * \param lqe    - is the quota entry associated with the identifier
 * \param global - is set to true when updating the record is of type
 *                 lquota_glb_rec. Otherwise, it is a lquota_slv_rec record.
 * \param rec    - is the updated record received from the master.
 */
int qsd_update_lqe(const struct lu_env *env, struct lquota_entry *lqe,
		   bool global, void *rec)
{
	ENTRY;

	LASSERT(lqe != NULL);
	LASSERT(!lqe_is_master(lqe));

	/* updating lqe is always serialized, no locking needed. */
	if (global) {
		struct lquota_glb_rec *glb_rec = (struct lquota_glb_rec *)rec;

		/* doesn't change quota enforcement if the quota entry is still
		 * using default quota. */
		if (LQUOTA_FLAG(glb_rec->qbr_time) & LQUOTA_FLAG_DEFAULT &&
		    glb_rec->qbr_hardlimit == 0 && glb_rec->qbr_softlimit == 0)
			RETURN(0);

		LQUOTA_DEBUG(lqe, "the ID has been set quota, so clear the"
			     " default quota flag");
		lqe->lqe_is_default = false;

		/* change enforcement status based on new hard/soft limit */
		if (lqe->lqe_id.qid_uid != 0 && (glb_rec->qbr_hardlimit != 0 ||
		    glb_rec->qbr_softlimit != 0))
			lqe->lqe_enforced = true;
		else
			lqe->lqe_enforced = false;

		LQUOTA_DEBUG(lqe, "updating global index hardlimit: %llu, "
			     "softlimit: %llu", glb_rec->qbr_hardlimit,
			     glb_rec->qbr_softlimit);
	} else {
		struct lquota_slv_rec *slv_rec = (struct lquota_slv_rec *)rec;

		lqe->lqe_granted = slv_rec->qsr_granted;

		LQUOTA_DEBUG(lqe, "updating slave index, granted:%llu",
			     slv_rec->qsr_granted);
	}

	RETURN(0);
}
