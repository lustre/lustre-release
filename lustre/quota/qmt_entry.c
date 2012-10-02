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

#include "qmt_internal.h"

/*
 * Initialize qmt-specific fields of quota entry.
 *
 * \param lqe - is the quota entry to initialize
 * \param arg - is the pointer to the qmt_pool_info structure
 */
static void qmt_lqe_init(struct lquota_entry *lqe, void *arg)
{
	LASSERT(lqe_is_master(lqe));

	lqe->lqe_revoke_time = 0;
	cfs_init_rwsem(&lqe->lqe_sem);
}

/*
 * Update a lquota entry. This is done by reading quota settings from the global
 * index. The lquota entry must be write locked.
 *
 * \param env - the environment passed by the caller
 * \param lqe - is the quota entry to refresh
 * \param arg - is the pointer to the qmt_pool_info structure
 */
static int qmt_lqe_read(const struct lu_env *env, struct lquota_entry *lqe,
			void *arg)
{
	struct qmt_thread_info	*qti = qmt_info(env);
	struct qmt_pool_info	*pool = (struct qmt_pool_info *)arg;
	int			 rc;
	ENTRY;

	LASSERT(lqe_is_master(lqe));

	/* read record from disk */
	rc = lquota_disk_read(env, pool->qpi_glb_obj[lqe->lqe_site->lqs_qtype],
			      &lqe->lqe_id, (struct dt_rec *)&qti->qti_glb_rec);

	switch (rc) {
	case -ENOENT:
		/* no such entry, assume quota isn't enforced for this user */
		lqe->lqe_enforced = false;
		break;
	case 0:
		/* copy quota settings from on-disk record */
		lqe->lqe_granted   = qti->qti_glb_rec.qbr_granted;
		lqe->lqe_hardlimit = qti->qti_glb_rec.qbr_hardlimit;
		lqe->lqe_softlimit = qti->qti_glb_rec.qbr_softlimit;
		lqe->lqe_gracetime = qti->qti_glb_rec.qbr_time;

		if (lqe->lqe_hardlimit == 0 && lqe->lqe_softlimit == 0)
			/* {hard,soft}limit=0 means no quota enforced */
			lqe->lqe_enforced = false;
		else
			lqe->lqe_enforced  = true;

		break;
	default:
		LQUOTA_ERROR(lqe, "failed to read quota entry from disk, rc:%d",
			     rc);
		RETURN(rc);
	}

	LQUOTA_DEBUG(lqe, "read");
	RETURN(0);
}

/*
 * Print lqe information for debugging.
 *
 * \param lqe - is the quota entry to debug
 * \param arg - is the pointer to the qmt_pool_info structure
 * \param msgdata - debug message
 * \param fmt     - format of debug message
 */
static void qmt_lqe_debug(struct lquota_entry *lqe, void *arg,
			  struct libcfs_debug_msg_data *msgdata,
			  const char *fmt, va_list args)
{
	struct qmt_pool_info	*pool = (struct qmt_pool_info *)arg;

	libcfs_debug_vmsg2(msgdata, fmt, args,
			   "qmt:%s pool:%d-%s id:"LPU64" enforced:%d hard:"LPU64
			   " soft:"LPU64" granted:"LPU64" time:"LPU64" qunit:"
			   LPU64" edquot:%d revoke:"LPU64"\n",
			   pool->qpi_qmt->qmt_svname,
			   pool->qpi_key & 0x0000ffff,
			   RES_NAME(pool->qpi_key >> 16),
			   lqe->lqe_id.qid_uid, lqe->lqe_enforced,
			   lqe->lqe_hardlimit, lqe->lqe_softlimit,
			   lqe->lqe_granted, lqe->lqe_gracetime,
			   lqe->lqe_qunit, lqe->lqe_edquot,
			   lqe->lqe_revoke_time);
}

/*
 * Vector of quota entry operations supported on the master
 */
struct lquota_entry_operations qmt_lqe_ops = {
	.lqe_init	= qmt_lqe_init,
	.lqe_read	= qmt_lqe_read,
	.lqe_debug	= qmt_lqe_debug,
};

/*
 * Reserve enough credits to update records in both the global index and
 * the slave index identified by \slv_obj
 *
 * \param env     - is the environment passed by the caller
 * \param lqe     - is the quota entry associated with the identifier
 *                  subject to the change
 * \param slv_obj - is the dt_object associated with the index file
 * \param restore - is a temporary storage for current quota settings which will
 *                  be restored if something goes wrong at index update time.
 */
struct thandle *qmt_trans_start_with_slv(const struct lu_env *env,
					 struct lquota_entry *lqe,
					 struct dt_object *slv_obj,
					 struct qmt_lqe_restore *restore)
{
	struct qmt_device	*qmt;
	struct thandle		*th;
	int			 rc;
	ENTRY;

	LASSERT(lqe != NULL);
	LASSERT(lqe_is_master(lqe));

	qmt = lqe2qpi(lqe)->qpi_qmt;

	if (slv_obj != NULL)
		LQUOTA_DEBUG(lqe, "declare write for slv "DFID,
			     PFID(lu_object_fid(&slv_obj->do_lu)));

	/* start transaction */
	th = dt_trans_create(env, qmt->qmt_child);
	if (IS_ERR(th))
		RETURN(th);

	if (slv_obj == NULL)
		/* quota settings on master are updated synchronously for the
		 * time being */
		th->th_sync = 1;

	/* reserve credits for global index update */
	rc = lquota_disk_declare_write(env, th, LQE_GLB_OBJ(lqe), &lqe->lqe_id);
	if (rc)
		GOTO(out, rc);

	if (slv_obj != NULL) {
		/* reserve credits for slave index update */
		rc = lquota_disk_declare_write(env, th, slv_obj, &lqe->lqe_id);
		if (rc)
			GOTO(out, rc);
	}

	/* start transaction */
	rc = dt_trans_start_local(env, qmt->qmt_child, th);
	if (rc)
		GOTO(out, rc);

	EXIT;
out:
	if (rc) {
		dt_trans_stop(env, qmt->qmt_child, th);
		th = ERR_PTR(rc);
		LQUOTA_ERROR(lqe, "failed to slv declare write for "DFID
			     ", rc:%d", PFID(lu_object_fid(&slv_obj->do_lu)),
			     rc);
	} else {
		restore->qlr_hardlimit = lqe->lqe_hardlimit;
		restore->qlr_softlimit = lqe->lqe_softlimit;
		restore->qlr_gracetime = lqe->lqe_gracetime;
		restore->qlr_granted   = lqe->lqe_granted;
		restore->qlr_qunit     = lqe->lqe_qunit;
	}
	return th;
}

/*
 * Reserve enough credits to update a record in the global index
 *
 * \param env     - is the environment passed by the caller
 * \param lqe     - is the quota entry to be modified in the global index
 * \param restore - is a temporary storage for current quota settings which will
 *                  be restored if something goes wrong at index update time.
 */
struct thandle *qmt_trans_start(const struct lu_env *env,
				struct lquota_entry *lqe,
				struct qmt_lqe_restore *restore)
{
	LQUOTA_DEBUG(lqe, "declare write");
	return qmt_trans_start_with_slv(env, lqe, NULL, restore);
}

/*
 * Update record associated with a quota entry in the global index.
 * If LQUOTA_BUMP_VER is set, then the global index version must also be
 * bumped.
 * The entry must be at least read locked, dirty and up-to-date.
 *
 * \param env   - the environment passed by the caller
 * \param th    - is the transaction handle to be used for the disk writes
 * \param lqe   - is the quota entry to udpate
 * \param obj   - is the dt_object associated with the index file
 * \param flags - can be LQUOTA_BUMP_VER or LQUOTA_SET_VER.
 * \param ver   - is used to return the new version of the index.
 *
 * \retval      - 0 on success and lqe dirty flag cleared,
 *                appropriate error on failure and uptodate flag cleared.
 */
int qmt_glb_write(const struct lu_env *env, struct thandle *th,
		  struct lquota_entry *lqe, __u32 flags, __u64 *ver)
{
	struct qmt_thread_info	*qti = qmt_info(env);
	struct lquota_glb_rec	*rec;
	int			 rc;
	ENTRY;

	LASSERT(lqe != NULL);
	LASSERT(lqe_is_master(lqe));
	LASSERT(lqe_is_locked(lqe));
	LASSERT(lqe->lqe_uptodate);
	LASSERT((flags & ~(LQUOTA_BUMP_VER | LQUOTA_SET_VER)) == 0);

	LQUOTA_DEBUG(lqe, "write glb");

	if (!lqe->lqe_enforced && lqe->lqe_granted == 0 &&
	    lqe->lqe_id.qid_uid != 0) {
		/* quota isn't enforced any more for this entry and there is no
		 * more space granted to slaves, let's just remove the entry
		 * from the index */
		rec = NULL;
	} else {
		rec = &qti->qti_glb_rec;

		/* fill global index with updated quota settings */
		rec->qbr_granted   = lqe->lqe_granted;
		rec->qbr_hardlimit = lqe->lqe_hardlimit;
		rec->qbr_softlimit = lqe->lqe_softlimit;
		rec->qbr_time      = lqe->lqe_gracetime;
	}

	/* write new quota settings */
	rc = lquota_disk_write(env, th, LQE_GLB_OBJ(lqe), &lqe->lqe_id,
			       (struct dt_rec *)rec, flags, ver);
	if (rc)
		/* we failed to write the new quota settings to disk, report
		 * error to caller who will restore the initial value */
		LQUOTA_ERROR(lqe, "failed to update global index, rc:%d", rc);

	RETURN(rc);
}

/*
 * Read from disk how much quota space is allocated to a slave.
 * This is done by reading records from the dedicated slave index file.
 * Return in \granted how much quota space is currently allocated to the
 * slave.
 * The entry must be at least read locked.
 *
 * \param env - the environment passed by the caller
 * \param lqe - is the quota entry associated with the identifier to look-up
 *              in the slave index
 * \param slv_obj - is the dt_object associated with the slave index
 * \param granted - is the output parameter where to return how much space
 *                  is granted to the slave.
 *
 * \retval    - 0 on success, appropriate error on failure
 */
int qmt_slv_read(const struct lu_env *env, struct lquota_entry *lqe,
		 struct dt_object *slv_obj, __u64 *granted)
{
	struct qmt_thread_info	*qti = qmt_info(env);
	struct lquota_slv_rec	*slv_rec = &qti->qti_slv_rec;
	int			 rc;
	ENTRY;

	LASSERT(lqe != NULL);
	LASSERT(lqe_is_master(lqe));
	LASSERT(lqe_is_locked(lqe));

	LQUOTA_DEBUG(lqe, "read slv "DFID,
		     PFID(lu_object_fid(&slv_obj->do_lu)));

	/* read slave record from disk */
	rc = lquota_disk_read(env, slv_obj, &lqe->lqe_id,
			      (struct dt_rec *)slv_rec);
	switch (rc) {
	case -ENOENT:
		*granted = 0;
		break;
	case 0:
		/* extract granted from on-disk record */
		*granted = slv_rec->qsr_granted;
		break;
	default:
		LQUOTA_ERROR(lqe, "failed to read slave record "DFID,
			     PFID(lu_object_fid(&slv_obj->do_lu)));
		RETURN(rc);
	}

	LQUOTA_DEBUG(lqe, "successful slv read "LPU64, *granted);

	RETURN(0);
}

/*
 * Update record in slave index file.
 * The entry must be at least read locked.
 *
 * \param env - the environment passed by the caller
 * \param th  - is the transaction handle to be used for the disk writes
 * \param lqe - is the dirty quota entry which will be updated at the same time
 *              as the slave index
 * \param slv_obj - is the dt_object associated with the slave index
 * \param flags - can be LQUOTA_BUMP_VER or LQUOTA_SET_VER.
 * \param ver   - is used to return the new version of the index.
 * \param granted - is the new amount of quota space owned by the slave
 *
 * \retval    - 0 on success, appropriate error on failure
 */
int qmt_slv_write(const struct lu_env *env, struct thandle *th,
		  struct lquota_entry *lqe, struct dt_object *slv_obj,
		  __u32 flags, __u64 *ver, __u64 granted)
{
	struct qmt_thread_info	*qti = qmt_info(env);
	struct lquota_slv_rec	*rec;
	int			 rc;
	ENTRY;

	LASSERT(lqe != NULL);
	LASSERT(lqe_is_master(lqe));
	LASSERT(lqe_is_locked(lqe));

	LQUOTA_DEBUG(lqe, "write slv "DFID" granted:"LPU64,
		     PFID(lu_object_fid(&slv_obj->do_lu)), granted);

	if (granted == 0) {
		/* this slave does not own any quota space for this ID any more,
		 * so let's just remove the entry from the index */
		rec = NULL;
	} else {
		rec = &qti->qti_slv_rec;

		/* updated space granted to this slave */
		rec->qsr_granted = granted;
	}

	/* write new granted space */
	rc = lquota_disk_write(env, th, slv_obj, &lqe->lqe_id,
			       (struct dt_rec *)rec, flags, ver);
	if (rc) {
		LQUOTA_ERROR(lqe, "failed to update slave index "DFID" granted:"
			     LPU64, PFID(lu_object_fid(&slv_obj->do_lu)),
			     granted);
		RETURN(rc);
	}

	RETURN(0);
}

/*
 * Check whether new limits are valid for this pool
 *
 * \param lqe  - is the quota entry subject to the setquota
 * \param hard - is the new hard limit
 * \param soft - is the new soft limit
 */
int qmt_validate_limits(struct lquota_entry *lqe, __u64 hard, __u64 soft)
{
	ENTRY;

	if (hard != 0 && soft > hard)
		/* soft limit must be less than hard limit */
		RETURN(-EINVAL);
	RETURN(0);
}
