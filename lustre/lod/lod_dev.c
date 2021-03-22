/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License version 2 for more details.  A copy is
 * included in the COPYING file that accompanied this code.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 * GPL HEADER END
 */
/*
 * Copyright  2009 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustre/lod/lod_dev.c
 *
 * Lustre Logical Object Device
 *
 * Author: Alex Zhuravlev <alexey.zhuravlev@intel.com>
 * Author: Mikhail Pershin <mike.pershin@intel.com>
 */
/**
 * The Logical Object Device (LOD) layer manages access to striped
 * objects (both regular files and directories). It implements the DT
 * device and object APIs and is responsible for creating, storing,
 * and loading striping information as an extended attribute of the
 * underlying OSD object. LOD is the server side analog of the LOV and
 * LMV layers on the client side.
 *
 * Metadata LU object stack (layers of the same compound LU object,
 * all have the same FID):
 *
 *        MDT
 *         |      MD API
 *        MDD
 *         |      DT API
 *        LOD
 *       /   \    DT API
 *     OSD   OSP
 *
 * During LOD object initialization the localness or remoteness of the
 * object FID dictates the choice between OSD and OSP.
 *
 * An LOD object (file or directory) with N stripes (each has a
 * different FID):
 *
 *          LOD
 *           |
 *   +---+---+---+...+
 *   |   |   |   |   |
 *   S0  S1  S2  S3  S(N-1)  OS[DP] objects, seen as DT objects by LOD
 *
 * When upper layers must access an object's stripes (which are
 * themselves OST or MDT LU objects) LOD finds these objects by their
 * FIDs and stores them as an array of DT object pointers on the
 * object. Declarations and operations on LOD objects are received by
 * LOD (as DT object operations) and performed on the underlying
 * OS[DP] object and (as needed) on the stripes. From the perspective
 * of LOD, a stripe-less file (created by mknod() or open with
 * O_LOV_DELAY_CREATE) is an object which does not yet have stripes,
 * while a non-striped directory (created by mkdir()) is an object
 * which will never have stripes.
 *
 * The LOD layer also implements a small subset of the OBD device API
 * to support MDT stack initialization and finalization (an MDD device
 * connects and disconnects itself to and from the underlying LOD
 * device), and pool management. In turn LOD uses the OBD device API
 * to connect it self to the underlying OSD, and to connect itself to
 * OSP devices representing the MDTs and OSTs that bear the stripes of
 * its objects.
 */

#define DEBUG_SUBSYSTEM S_MDS

#include <linux/kthread.h>
#include <obd_class.h>
#include <md_object.h>
#include <lustre_fid.h>
#include <uapi/linux/lustre/lustre_param.h>
#include <lustre_update.h>
#include <lustre_log.h>
#include <lustre_lmv.h>

#include "lod_internal.h"

static const char lod_update_log_name[] = "update_log";
static const char lod_update_log_dir_name[] = "update_log_dir";

/*
 * Lookup target by FID.
 *
 * Lookup MDT/OST target index by FID. Type of the target can be
 * specific or any.
 *
 * \param[in] env		LU environment provided by the caller
 * \param[in] lod		lod device
 * \param[in] fid		FID
 * \param[out] tgt		result target index
 * \param[in] type		expected type of the target:
 *				LU_SEQ_RANGE_{MDT,OST,ANY}
 *
 * \retval 0			on success
 * \retval negative		negated errno on error
 **/
int lod_fld_lookup(const struct lu_env *env, struct lod_device *lod,
		   const struct lu_fid *fid, u32 *tgt, int *type)
{
	struct lu_seq_range range = { 0 };
	struct lu_server_fld *server_fld;
	int rc;

	ENTRY;

	if (!fid_is_sane(fid)) {
		CERROR("%s: invalid FID "DFID"\n", lod2obd(lod)->obd_name,
		       PFID(fid));
		RETURN(-EIO);
	}

	if (fid_is_idif(fid)) {
		*tgt = fid_idif_ost_idx(fid);
		*type = LU_SEQ_RANGE_OST;
		RETURN(0);
	}

	if (fid_is_update_log(fid) || fid_is_update_log_dir(fid)) {
		*tgt = fid_oid(fid);
		*type = LU_SEQ_RANGE_MDT;
		RETURN(0);
	}

	if (!lod->lod_initialized || (!fid_seq_in_fldb(fid_seq(fid)))) {
		LASSERT(lu_site2seq(lod2lu_dev(lod)->ld_site) != NULL);

		*tgt = lu_site2seq(lod2lu_dev(lod)->ld_site)->ss_node_id;
		*type = LU_SEQ_RANGE_MDT;
		RETURN(0);
	}

	server_fld = lu_site2seq(lod2lu_dev(lod)->ld_site)->ss_server_fld;
	if (!server_fld)
		RETURN(-EIO);

	fld_range_set_type(&range, *type);
	rc = fld_server_lookup(env, server_fld, fid_seq(fid), &range);
	if (rc != 0)
		RETURN(rc);

	*tgt = range.lsr_index;
	*type = range.lsr_flags;

	CDEBUG(D_INFO, "%s: got tgt %x for sequence: %#llx\n",
	       lod2obd(lod)->obd_name, *tgt, fid_seq(fid));

	RETURN(0);
}

/* Slab for OSD object allocation */
struct kmem_cache *lod_object_kmem;

/* Slab for dt_txn_callback */
struct kmem_cache *lod_txn_callback_kmem;
static struct lu_kmem_descr lod_caches[] = {
	{
		.ckd_cache = &lod_object_kmem,
		.ckd_name  = "lod_obj",
		.ckd_size  = sizeof(struct lod_object)
	},
	{
		.ckd_cache = &lod_txn_callback_kmem,
		.ckd_name  = "lod_txn_callback",
		.ckd_size  = sizeof(struct dt_txn_callback)
	},
	{
		.ckd_cache = NULL
	}
};

static struct lu_device *lod_device_fini(const struct lu_env *env,
					 struct lu_device *d);

/**
 * Implementation of lu_device_operations::ldo_object_alloc() for LOD
 *
 * Allocates and initializes LOD's slice in the given object.
 *
 * see include/lu_object.h for the details.
 */
static struct lu_object *lod_object_alloc(const struct lu_env *env,
					  const struct lu_object_header *hdr,
					  struct lu_device *dev)
{
	struct lod_object *lod_obj;
	struct lu_object *lu_obj;

	ENTRY;

	OBD_SLAB_ALLOC_PTR_GFP(lod_obj, lod_object_kmem, GFP_NOFS);
	if (!lod_obj)
		RETURN(ERR_PTR(-ENOMEM));

	mutex_init(&lod_obj->ldo_layout_mutex);
	lu_obj = lod2lu_obj(lod_obj);
	dt_object_init(&lod_obj->ldo_obj, NULL, dev);
	lod_obj->ldo_obj.do_ops = &lod_obj_ops;
	lu_obj->lo_ops = &lod_lu_obj_ops;

	RETURN(lu_obj);
}

/**
 * Process the config log for all sub device.
 *
 * The function goes through all the targets in the given table
 * and apply given configuration command on to the targets.
 * Used to cleanup the targets at unmount.
 *
 * \param[in] env		LU environment provided by the caller
 * \param[in] lod		lod device
 * \param[in] ltd		target's table to go through
 * \param[in] lcfg		configuration command to apply
 *
 * \retval 0			on success
 * \retval negative		negated errno on error
 **/
static int lod_sub_process_config(const struct lu_env *env,
				 struct lod_device *lod,
				 struct lod_tgt_descs *ltd,
				 struct lustre_cfg *lcfg)
{
	struct lu_device *next;
	struct lu_tgt_desc *tgt;
	int rc = 0;

	lod_getref(ltd);
	ltd_foreach_tgt(ltd, tgt) {
		int rc1;

		LASSERT(tgt && tgt->ltd_tgt);
		next = &tgt->ltd_tgt->dd_lu_dev;
		rc1 = next->ld_ops->ldo_process_config(env, next, lcfg);
		if (rc1) {
			CERROR("%s: error cleaning up LOD index %u: cmd %#x : rc = %d\n",
			       lod2obd(lod)->obd_name, tgt->ltd_index,
			       lcfg->lcfg_command, rc1);
			rc = rc1;
		}
	}
	lod_putref(lod, ltd);
	return rc;
}

struct lod_recovery_data {
	struct lod_device	*lrd_lod;
	struct lod_tgt_desc	*lrd_ltd;
	struct task_struct	**lrd_task;
	u32			lrd_idx;
	struct lu_env		lrd_env;
	struct completion	*lrd_started;
};


/**
 * process update recovery record
 *
 * Add the update recovery recode to the update recovery list in
 * lod_recovery_data. Then the recovery thread (target_recovery_thread)
 * will redo these updates.
 *
 * \param[in]env	execution environment
 * \param[in]llh	log handle of update record
 * \param[in]rec	update record to be replayed
 * \param[in]data	update recovery data which holds the necessary
 *                      arguments for recovery (see struct lod_recovery_data)
 *
 * \retval		0 if the record is processed successfully.
 * \retval		negative errno if the record processing fails.
 */
static int lod_process_recovery_updates(const struct lu_env *env,
					struct llog_handle *llh,
					struct llog_rec_hdr *rec,
					void *data)
{
	struct lod_recovery_data *lrd = data;
	struct llog_cookie *cookie = &lod_env_info(env)->lti_cookie;
	struct lu_target *lut;
	u32 index = 0;

	ENTRY;

	if (!lrd->lrd_ltd) {
		int rc;

		rc = lodname2mdt_index(lod2obd(lrd->lrd_lod)->obd_name, &index);
		if (rc != 0)
			return rc;
	} else {
		index = lrd->lrd_ltd->ltd_index;
	}

	if (rec->lrh_len !=
		llog_update_record_size((struct llog_update_record *)rec)) {
		CERROR("%s: broken update record! index %u "DFID".%u: rc = %d\n",
		       lod2obd(lrd->lrd_lod)->obd_name, index,
		       PFID(&llh->lgh_id.lgl_oi.oi_fid), rec->lrh_index, -EIO);
		return -EINVAL;
	}

	cookie->lgc_lgl = llh->lgh_id;
	cookie->lgc_index = rec->lrh_index;
	cookie->lgc_subsys = LLOG_UPDATELOG_ORIG_CTXT;

	CDEBUG(D_HA, "%s: process recovery updates "DFID".%u\n",
	       lod2obd(lrd->lrd_lod)->obd_name,
	       PFID(&llh->lgh_id.lgl_oi.oi_fid), rec->lrh_index);
	lut = lod2lu_dev(lrd->lrd_lod)->ld_site->ls_tgt;

	if (lut->lut_obd->obd_stopping ||
	    lut->lut_obd->obd_abort_recovery)
		return -ESHUTDOWN;

	return insert_update_records_to_replay_list(lut->lut_tdtd,
					(struct llog_update_record *)rec,
					cookie, index);
}

/**
 * recovery thread for update log
 *
 * Start recovery thread and prepare the sub llog, then it will retrieve
 * the update records from the correpondent MDT and do recovery.
 *
 * \param[in] arg	pointer to the recovery data
 *
 * \retval		0 if recovery succeeds
 * \retval		negative errno if recovery failed.
 */
static int lod_sub_recovery_thread(void *arg)
{
	struct lod_recovery_data *lrd = arg;
	struct lod_device *lod = lrd->lrd_lod;
	struct dt_device *dt;
	struct llog_ctxt *ctxt = NULL;
	struct lu_env *env = &lrd->lrd_env;
	struct lu_target *lut;
	struct lu_tgt_desc *mdt = NULL;
	time64_t start;
	int retries = 0;
	int rc;

	ENTRY;

	lut = lod2lu_dev(lod)->ld_site->ls_tgt;
	atomic_inc(&lut->lut_tdtd->tdtd_recovery_threads_count);
	if (!lrd->lrd_ltd)
		dt = lod->lod_child;
	else
		dt = lrd->lrd_ltd->ltd_tgt;

	start = ktime_get_real_seconds();
	complete(lrd->lrd_started);

again:

	if (unlikely(OBD_FAIL_PRECHECK(OBD_FAIL_TGT_RECOVERY_CONNECT)) &&
	    lrd->lrd_ltd) {
		OBD_FAIL_TIMEOUT(OBD_FAIL_TGT_RECOVERY_CONNECT, cfs_fail_val);
		rc = -EIO;
	} else {
		rc = lod_sub_prep_llog(env, lod, dt, lrd->lrd_idx);
	}
	if (!rc && !lod->lod_child->dd_rdonly) {
		/* Process the recovery record */
		ctxt = llog_get_context(dt->dd_lu_dev.ld_obd,
					LLOG_UPDATELOG_ORIG_CTXT);
		LASSERT(ctxt != NULL);
		LASSERT(ctxt->loc_handle != NULL);

		rc = llog_cat_process(env, ctxt->loc_handle,
				      lod_process_recovery_updates, lrd, 0, 0);
	}

	if (rc < 0) {
		struct lu_device *top_device;

		top_device = lod->lod_dt_dev.dd_lu_dev.ld_site->ls_top_dev;
		/*
		 * Because the remote target might failover at the same time,
		 * let's retry here
		 */
		if ((rc == -ETIMEDOUT || rc == -EAGAIN || rc == -EIO) &&
		     dt != lod->lod_child &&
		    !top_device->ld_obd->obd_abort_recovery &&
		    !top_device->ld_obd->obd_stopping) {
			if (ctxt) {
				if (ctxt->loc_handle)
					llog_cat_close(env,
						       ctxt->loc_handle);
				llog_ctxt_put(ctxt);
			}
			retries++;
			CDEBUG(D_HA, "%s get update log failed %d, retry\n",
			       dt->dd_lu_dev.ld_obd->obd_name, rc);
			goto again;
		}

		CERROR("%s get update log failed: rc = %d\n",
		       dt->dd_lu_dev.ld_obd->obd_name, rc);
		llog_ctxt_put(ctxt);

		spin_lock(&top_device->ld_obd->obd_dev_lock);
		if (!top_device->ld_obd->obd_abort_recovery &&
		    !top_device->ld_obd->obd_stopping)
			top_device->ld_obd->obd_abort_recovery = 1;
		spin_unlock(&top_device->ld_obd->obd_dev_lock);

		GOTO(out, rc);
	}
	llog_ctxt_put(ctxt);

	CDEBUG(D_HA, "%s retrieved update log, duration %lld, retries %d\n",
	       dt->dd_lu_dev.ld_obd->obd_name, ktime_get_real_seconds() - start,
	       retries);

	spin_lock(&lod->lod_lock);
	if (!lrd->lrd_ltd)
		lod->lod_child_got_update_log = 1;
	else
		lrd->lrd_ltd->ltd_got_update_log = 1;

	if (!lod->lod_child_got_update_log) {
		spin_unlock(&lod->lod_lock);
		GOTO(out, rc = 0);
	}

	lod_foreach_mdt(lod, mdt) {
		if (!mdt->ltd_got_update_log) {
			spin_unlock(&lod->lod_lock);
			GOTO(out, rc = 0);
		}
	}
	lut->lut_tdtd->tdtd_replay_ready = 1;
	spin_unlock(&lod->lod_lock);

	CDEBUG(D_HA, "%s got update logs from all MDTs.\n",
	       lut->lut_obd->obd_name);
	wake_up(&lut->lut_obd->obd_next_transno_waitq);
	EXIT;

out:
	atomic_dec(&lut->lut_tdtd->tdtd_recovery_threads_count);
	wake_up(&lut->lut_tdtd->tdtd_recovery_threads_waitq);
	if (xchg(lrd->lrd_task, NULL) == NULL)
		/* Someone is waiting for us to finish, need
		 * to synchronize cleanly.
		 */
		wait_var_event(lrd, kthread_should_stop());
	lu_env_fini(env);
	OBD_FREE_PTR(lrd);
	return 0;
}

/**
 * finish sub llog context
 *
 * Stop update recovery thread for the sub device, then cleanup the
 * correspondent llog ctxt.
 *
 * \param[in] env      execution environment
 * \param[in] lod      lod device to do update recovery
 * \param[in] thread   recovery thread on this sub device
 */
void lod_sub_fini_llog(const struct lu_env *env,
		       struct dt_device *dt, struct task_struct **thread)
{
	struct obd_device *obd;
	struct llog_ctxt *ctxt;
	struct task_struct *task = NULL;

	ENTRY;

	obd = dt->dd_lu_dev.ld_obd;
	CDEBUG(D_INFO, "%s: finish sub llog\n", obd->obd_name);
	/* Wait for recovery thread to complete */
	if (thread)
		task = xchg(thread, NULL);
	if (task)
		kthread_stop(task);

	ctxt = llog_get_context(obd, LLOG_UPDATELOG_ORIG_CTXT);
	if (!ctxt)
		RETURN_EXIT;

	if (ctxt->loc_handle)
		llog_cat_close(env, ctxt->loc_handle);

	llog_cleanup(env, ctxt);

	RETURN_EXIT;
}

/**
 * Extract MDT target index from a device name.
 *
 * a helper function to extract index from the given device name
 * like "fsname-MDTxxxx-mdtlov"
 *
 * \param[in] lodname		device name
 * \param[out] mdt_index	extracted index
 *
 * \retval 0		on success
 * \retval -EINVAL	if the name is invalid
 */
int lodname2mdt_index(char *lodname, u32 *mdt_index)
{
	u32 index;
	const char *ptr, *tmp;
	int rc;

	/* 1.8 configs don't have "-MDT0000" at the end */
	ptr = strstr(lodname, "-MDT");
	if (!ptr) {
		*mdt_index = 0;
		return 0;
	}

	ptr = strrchr(lodname, '-');
	if (!ptr) {
		rc = -EINVAL;
		CERROR("invalid MDT index in '%s': rc = %d\n", lodname, rc);
		return rc;
	}

	if (strncmp(ptr, "-mdtlov", 7) != 0) {
		rc = -EINVAL;
		CERROR("invalid MDT index in '%s': rc = %d\n", lodname, rc);
		return rc;
	}

	if ((unsigned long)ptr - (unsigned long)lodname <= 8) {
		rc = -EINVAL;
		CERROR("invalid MDT index in '%s': rc = %d\n", lodname, rc);
		return rc;
	}

	if (strncmp(ptr - 8, "-MDT", 4) != 0) {
		rc = -EINVAL;
		CERROR("invalid MDT index in '%s': rc = %d\n", lodname, rc);
		return rc;
	}

	rc = target_name2index(ptr - 7, &index, &tmp);
	if (rc < 0 || rc & LDD_F_SV_ALL || *tmp != '-') {
		rc = -EINVAL;
		CERROR("invalid MDT index in '%s': rc = %d\n", lodname, rc);
		return rc;
	}
	*mdt_index = index;
	return 0;
}

/**
 * Init sub llog context
 *
 * Setup update llog ctxt for update recovery threads, then start the
 * recovery thread (lod_sub_recovery_thread) to read update llog from
 * the correspondent MDT to do update recovery.
 *
 * \param[in] env	execution environment
 * \param[in] lod	lod device to do update recovery
 * \param[in] dt	sub dt device for which the recovery thread is
 *
 * \retval		0 if initialization succeeds.
 * \retval		negative errno if initialization fails.
 */
int lod_sub_init_llog(const struct lu_env *env, struct lod_device *lod,
		      struct dt_device *dt)
{
	struct obd_device *obd;
	struct lod_recovery_data *lrd = NULL;
	DECLARE_COMPLETION_ONSTACK(started);
	struct task_struct **taskp;
	struct task_struct *task;
	struct lod_tgt_desc *subtgt = NULL;
	u32 index;
	u32 master_index;
	int rc;

	ENTRY;

	rc = lodname2mdt_index(lod2obd(lod)->obd_name, &master_index);
	if (rc != 0)
		RETURN(rc);

	OBD_ALLOC_PTR(lrd);
	if (!lrd)
		RETURN(-ENOMEM);

	if (lod->lod_child == dt) {
		taskp = &lod->lod_child_recovery_task;
		index = master_index;
	} else {
		struct lu_tgt_desc *mdt;

		lod_foreach_mdt(lod, mdt) {
			if (mdt->ltd_tgt == dt) {
				index = mdt->ltd_index;
				subtgt = mdt;
				break;
			}
		}
		LASSERT(subtgt != NULL);
		taskp = &subtgt->ltd_recovery_task;
	}

	CDEBUG(D_INFO, "%s init sub log %s\n", lod2obd(lod)->obd_name,
	       dt->dd_lu_dev.ld_obd->obd_name);
	lrd->lrd_lod = lod;
	lrd->lrd_ltd = subtgt;
	lrd->lrd_task = taskp;
	lrd->lrd_idx = index;
	lrd->lrd_started = &started;

	obd = dt->dd_lu_dev.ld_obd;
	obd->obd_lvfs_ctxt.dt = dt;
	rc = llog_setup(env, obd, &obd->obd_olg, LLOG_UPDATELOG_ORIG_CTXT,
			NULL, &llog_common_cat_ops);
	if (rc < 0) {
		CERROR("%s: cannot setup updatelog llog: rc = %d\n",
		       obd->obd_name, rc);
		GOTO(free_lrd, rc);
	}

	rc = lu_env_init(&lrd->lrd_env, LCT_LOCAL | LCT_MD_THREAD);
	if (rc != 0) {
		CERROR("%s: can't initialize env: rc = %d\n",
		       lod2obd(lod)->obd_name, rc);
		GOTO(free_lrd, rc);
	}

	/* Start the recovery thread */
	task = kthread_create(lod_sub_recovery_thread, lrd, "lod%04x_rec%04x",
			      master_index, index);
	if (IS_ERR(task)) {
		rc = PTR_ERR(task);
		CERROR("%s: cannot start recovery thread: rc = %d\n",
		       obd->obd_name, rc);
		lu_env_fini(&lrd->lrd_env);
		GOTO(out_llog, rc);
	}
	*taskp = task;
	wake_up_process(task);
	wait_for_completion(&started);

	RETURN(0);
out_llog:
	lod_sub_fini_llog(env, dt, taskp);
free_lrd:
	OBD_FREE_PTR(lrd);
	RETURN(rc);
}

/**
 * Stop sub recovery thread
 *
 * Stop sub recovery thread on all subs.
 *
 * \param[in] env	execution environment
 * \param[in] lod	lod device to do update recovery
 */
static void lod_sub_stop_recovery_threads(const struct lu_env *env,
					  struct lod_device *lod)
{
	struct task_struct *task;
	struct lu_tgt_desc *mdt;

	/*
	 * Stop the update log commit cancel threads and finish master
	 * llog ctxt
	 */
	task = xchg(&lod->lod_child_recovery_task, NULL);
	if (task)
		kthread_stop(task);

	lod_getref(&lod->lod_mdt_descs);
	lod_foreach_mdt(lod, mdt) {
		task = xchg(&mdt->ltd_recovery_task, NULL);
		if (task)
			kthread_stop(task);
	}
	lod_putref(lod, &lod->lod_mdt_descs);
}

/**
 * finish all sub llog
 *
 * cleanup all of sub llog ctxt on the LOD.
 *
 * \param[in] env	execution environment
 * \param[in] lod	lod device to do update recovery
 */
static void lod_sub_fini_all_llogs(const struct lu_env *env,
				   struct lod_device *lod)
{
	struct lu_tgt_desc *mdt;

	/*
	 * Stop the update log commit cancel threads and finish master
	 * llog ctxt
	 */
	lod_sub_fini_llog(env, lod->lod_child,
			  &lod->lod_child_recovery_task);
	lod_getref(&lod->lod_mdt_descs);
	lod_foreach_mdt(lod, mdt)
		lod_sub_fini_llog(env, mdt->ltd_tgt,
				  &mdt->ltd_recovery_task);
	lod_putref(lod, &lod->lod_mdt_descs);
}

static char *lod_show_update_logs_retrievers(void *data, int *size, int *count)
{
	struct lod_device *lod = (struct lod_device *)data;
	struct lu_target *lut = lod2lu_dev(lod)->ld_site->ls_tgt;
	struct lu_tgt_desc *mdt = NULL;
	char *buf;
	int len = 0;
	int rc;
	int i;

	*count = atomic_read(&lut->lut_tdtd->tdtd_recovery_threads_count);
	if (*count == 0) {
		*size = 0;
		return NULL;
	}

	*size = 5 * *count + 1;
	OBD_ALLOC(buf, *size);
	if (!buf)
		return NULL;

	*count = 0;
	memset(buf, 0, *size);

	if (!lod->lod_child_got_update_log) {
		rc = lodname2mdt_index(lod2obd(lod)->obd_name, &i);
		LASSERTF(rc == 0, "Fail to parse target index: rc = %d\n", rc);

		rc = scnprintf(buf + len, *size - len, " %04x", i);
		LASSERT(rc > 0);

		len += rc;
		(*count)++;
	}

	lod_foreach_mdt(lod, mdt) {
		if (!mdt->ltd_got_update_log) {
			rc = scnprintf(buf + len, *size - len, " %04x",
				       mdt->ltd_index);
			if (unlikely(rc <= 0))
				break;

			len += rc;
			(*count)++;
		}
	}

	return buf;
}

/**
 * Prepare distribute txn
 *
 * Prepare distribute txn structure for LOD
 *
 * \param[in] env	execution environment
 * \param[in] lod_device  LOD device
 *
 * \retval		0 if preparation succeeds.
 * \retval		negative errno if preparation fails.
 */
static int lod_prepare_distribute_txn(const struct lu_env *env,
				      struct lod_device *lod)
{
	struct target_distribute_txn_data *tdtd;
	struct lu_target *lut;
	int rc;

	ENTRY;

	/* Init update recovery data */
	OBD_ALLOC_PTR(tdtd);
	if (!tdtd)
		RETURN(-ENOMEM);

	lut = lod2lu_dev(lod)->ld_site->ls_tgt;
	tdtd->tdtd_dt = &lod->lod_dt_dev;
	rc = distribute_txn_init(env, lut, tdtd,
		lu_site2seq(lod2lu_dev(lod)->ld_site)->ss_node_id);

	if (rc < 0) {
		CERROR("%s: cannot init distribute txn: rc = %d\n",
		       lod2obd(lod)->obd_name, rc);
		OBD_FREE_PTR(tdtd);
		RETURN(rc);
	}

	tdtd->tdtd_show_update_logs_retrievers =
		lod_show_update_logs_retrievers;
	tdtd->tdtd_show_retrievers_cbdata = lod;

	lut->lut_tdtd = tdtd;

	RETURN(0);
}

/**
 * Finish distribute txn
 *
 * Release the resource holding by distribute txn, i.e. stop distribute
 * txn thread.
 *
 * \param[in] env	execution environment
 * \param[in] lod	lod device
 */
static void lod_fini_distribute_txn(const struct lu_env *env,
				    struct lod_device *lod)
{
	struct lu_target *lut;

	lut = lod2lu_dev(lod)->ld_site->ls_tgt;
	target_recovery_fini(lut->lut_obd);
	if (!lut->lut_tdtd)
		return;

	distribute_txn_fini(env, lut->lut_tdtd);

	OBD_FREE_PTR(lut->lut_tdtd);
	lut->lut_tdtd = NULL;
}

/**
 * Implementation of lu_device_operations::ldo_process_config() for LOD
 *
 * The method is called by the configuration subsystem during setup,
 * cleanup and when the configuration changes. The method processes
 * few specific commands like adding/removing the targets, changing
 * the runtime parameters.

 * \param[in] env		LU environment provided by the caller
 * \param[in] dev		lod device
 * \param[in] lcfg		configuration command to apply
 *
 * \retval 0			on success
 * \retval negative		negated errno on error
 *
 * The examples are below.
 *
 * Add osc config log:
 * marker  20 (flags=0x01, v2.2.49.56) lustre-OST0001  'add osc'
 * add_uuid  nid=192.168.122.162@tcp(0x20000c0a87aa2)  0:  1:nidxxx
 * attach    0:lustre-OST0001-osc-MDT0001  1:osc  2:lustre-MDT0001-mdtlov_UUID
 * setup     0:lustre-OST0001-osc-MDT0001  1:lustre-OST0001_UUID  2:nid
 * lov_modify_tgts add 0:lustre-MDT0001-mdtlov  1:lustre-OST0001_UUID  2:1  3:1
 * marker  20 (flags=0x02, v2.2.49.56) lustre-OST0001  'add osc'
 *
 * Add mdc config log:
 * marker  10 (flags=0x01, v2.2.49.56) lustre-MDT0000  'add osp'
 * add_uuid  nid=192.168.122.162@tcp(0x20000c0a87aa2)  0:  1:nid
 * attach 0:lustre-MDT0000-osp-MDT0001  1:osp  2:lustre-MDT0001-mdtlov_UUID
 * setup     0:lustre-MDT0000-osp-MDT0001  1:lustre-MDT0000_UUID  2:nid
 * modify_mdc_tgts add 0:lustre-MDT0001  1:lustre-MDT0000_UUID  2:0  3:1
 * marker  10 (flags=0x02, v2.2.49.56) lustre-MDT0000_UUID  'add osp'
 */
static int lod_process_config(const struct lu_env *env,
			      struct lu_device *dev,
			      struct lustre_cfg *lcfg)
{
	struct lod_device *lod = lu2lod_dev(dev);
	struct lu_device *next = &lod->lod_child->dd_lu_dev;
	char *arg1;
	int rc = 0;

	ENTRY;

	switch (lcfg->lcfg_command) {
	case LCFG_LOV_DEL_OBD:
	case LCFG_LOV_ADD_INA:
	case LCFG_LOV_ADD_OBD:
	case LCFG_ADD_MDC: {
		u32 index;
		u32 mdt_index;
		int gen;
		/*
		 * lov_modify_tgts add  0:lov_mdsA  1:osp  2:0  3:1
		 * modify_mdc_tgts add  0:lustre-MDT0001
		 *		      1:lustre-MDT0001-mdc0002
		 *		      2:2  3:1
		 */
		arg1 = lustre_cfg_string(lcfg, 1);

		if (sscanf(lustre_cfg_buf(lcfg, 2), "%d", &index) != 1)
			GOTO(out, rc = -EINVAL);
		if (sscanf(lustre_cfg_buf(lcfg, 3), "%d", &gen) != 1)
			GOTO(out, rc = -EINVAL);

		if (lcfg->lcfg_command == LCFG_LOV_ADD_OBD) {
			u32 mdt_index;

			rc = lodname2mdt_index(lustre_cfg_string(lcfg, 0),
					       &mdt_index);
			if (rc != 0)
				GOTO(out, rc);

			rc = lod_add_device(env, lod, arg1, index, gen,
					    mdt_index, LUSTRE_OSC_NAME, 1);
		} else if (lcfg->lcfg_command == LCFG_ADD_MDC) {
			mdt_index = index;
			rc = lod_add_device(env, lod, arg1, index, gen,
					    mdt_index, LUSTRE_MDC_NAME, 1);
		} else if (lcfg->lcfg_command == LCFG_LOV_ADD_INA) {
			/*FIXME: Add mdt_index for LCFG_LOV_ADD_INA*/
			mdt_index = 0;
			rc = lod_add_device(env, lod, arg1, index, gen,
					    mdt_index, LUSTRE_OSC_NAME, 0);
		} else {
			rc = lod_del_device(env, lod, &lod->lod_ost_descs,
					    arg1, index, gen);
		}

		break;
	}

	case LCFG_PARAM: {
		struct obd_device *obd;
		ssize_t count;
		char *param;

		/*
		 * Check if it is activate/deactivate mdc
		 * lustre-MDTXXXX-osp-MDTXXXX.active=1
		 */
		param = lustre_cfg_buf(lcfg, 1);
		if (strstr(param, "osp") && strstr(param, ".active=")) {
			struct lod_tgt_desc *sub_tgt = NULL;
			struct lu_tgt_desc *mdt;
			char *ptr;
			char *tmp;

			ptr = strstr(param, ".");
			*ptr = '\0';
			obd = class_name2obd(param);
			if (!obd) {
				CERROR("%s: can not find %s: rc = %d\n",
				       lod2obd(lod)->obd_name, param, -EINVAL);
				*ptr = '.';
				GOTO(out, rc);
			}

			lod_foreach_mdt(lod, mdt) {
				if (mdt->ltd_tgt->dd_lu_dev.ld_obd == obd) {
					sub_tgt = mdt;
					break;
				}
			}

			if (!sub_tgt) {
				CERROR("%s: can not find %s: rc = %d\n",
				       lod2obd(lod)->obd_name, param, -EINVAL);
				*ptr = '.';
				GOTO(out, rc);
			}

			*ptr = '.';
			tmp = strstr(param, "=");
			tmp++;
			if (*tmp == '1') {
				struct llog_ctxt *ctxt;

				obd = sub_tgt->ltd_tgt->dd_lu_dev.ld_obd;
				ctxt = llog_get_context(obd,
						LLOG_UPDATELOG_ORIG_CTXT);
				if (!ctxt) {
					rc = llog_setup(env, obd, &obd->obd_olg,
						       LLOG_UPDATELOG_ORIG_CTXT,
						    NULL, &llog_common_cat_ops);
					if (rc < 0)
						GOTO(out, rc);
				} else {
					llog_ctxt_put(ctxt);
				}
				rc = lod_sub_prep_llog(env, lod,
						       sub_tgt->ltd_tgt,
						       sub_tgt->ltd_index);
				if (rc == 0)
					sub_tgt->ltd_active = 1;
			} else {
				lod_sub_fini_llog(env, sub_tgt->ltd_tgt,
						  NULL);
				sub_tgt->ltd_active = 0;
			}
			GOTO(out, rc);
		}


		if (strstr(param, PARAM_LOD) != NULL)
			count = class_modify_config(lcfg, PARAM_LOD,
						    &lod->lod_dt_dev.dd_kobj);
		else
			count = class_modify_config(lcfg, PARAM_LOV,
						    &lod->lod_dt_dev.dd_kobj);
		rc = count > 0 ? 0 : count;
		GOTO(out, rc);
	}
	case LCFG_PRE_CLEANUP: {
		lod_sub_process_config(env, lod, &lod->lod_mdt_descs, lcfg);
		lod_sub_process_config(env, lod, &lod->lod_ost_descs, lcfg);
		OBD_FAIL_TIMEOUT(OBD_FAIL_TGT_RECOVERY_CONNECT, cfs_fail_val * 2);
		next = &lod->lod_child->dd_lu_dev;
		rc = next->ld_ops->ldo_process_config(env, next, lcfg);
		if (rc != 0)
			CDEBUG(D_HA, "%s: can't process %u: %d\n",
			       lod2obd(lod)->obd_name, lcfg->lcfg_command, rc);

		lod_sub_stop_recovery_threads(env, lod);
		lod_fini_distribute_txn(env, lod);
		lod_sub_fini_all_llogs(env, lod);
		break;
	}
	case LCFG_CLEANUP: {
		if (lod->lod_md_root) {
			dt_object_put(env, &lod->lod_md_root->ldo_obj);
			lod->lod_md_root = NULL;
		}

		/*
		 * do cleanup on underlying storage only when
		 * all OSPs are cleaned up, as they use that OSD as well
		 */
		lu_dev_del_linkage(dev->ld_site, dev);
		lod_sub_process_config(env, lod, &lod->lod_mdt_descs, lcfg);
		lod_sub_process_config(env, lod, &lod->lod_ost_descs, lcfg);
		next = &lod->lod_child->dd_lu_dev;
		rc = next->ld_ops->ldo_process_config(env, next, lcfg);
		if (rc)
			CERROR("%s: can't process %u: rc = %d\n",
			       lod2obd(lod)->obd_name, lcfg->lcfg_command, rc);

		rc = obd_disconnect(lod->lod_child_exp);
		if (rc)
			CERROR("error in disconnect from storage: rc = %d\n",
			       rc);
		break;
	}
	default:
		CERROR("%s: unknown command %u\n", lod2obd(lod)->obd_name,
		       lcfg->lcfg_command);
		rc = -EINVAL;
		break;
	}

out:
	RETURN(rc);
}

/**
 * Implementation of lu_device_operations::ldo_recovery_complete() for LOD
 *
 * The method is called once the recovery is complete. This implementation
 * distributes the notification to all the known targets.
 *
 * see include/lu_object.h for the details
 */
static int lod_recovery_complete(const struct lu_env *env,
				 struct lu_device *dev)
{
	struct lod_device *lod = lu2lod_dev(dev);
	struct lu_device *next = &lod->lod_child->dd_lu_dev;
	struct lod_tgt_desc *tgt;
	int rc;

	ENTRY;

	LASSERT(lod->lod_recovery_completed == 0);
	lod->lod_recovery_completed = 1;

	rc = next->ld_ops->ldo_recovery_complete(env, next);

	lod_getref(&lod->lod_ost_descs);
	if (lod->lod_ost_descs.ltd_tgts_size > 0) {
		lod_foreach_ost(lod, tgt) {
			LASSERT(tgt && tgt->ltd_tgt);
			next = &tgt->ltd_tgt->dd_lu_dev;
			rc = next->ld_ops->ldo_recovery_complete(env, next);
			if (rc)
				CERROR("%s: can't complete recovery on #%d: rc = %d\n",
				       lod2obd(lod)->obd_name, tgt->ltd_index,
				       rc);
		}
	}
	lod_putref(lod, &lod->lod_ost_descs);
	RETURN(rc);
}

/**
 * Init update logs on all sub device
 *
 * LOD initialize update logs on all of sub devices. Because the initialization
 * process might need FLD lookup, see llog_osd_open()->dt_locate()->...->
 * lod_object_init(), this API has to be called after LOD is initialized.
 * \param[in] env	execution environment
 * \param[in] lod	lod device
 *
 * \retval		0 if update log is initialized successfully.
 * \retval		negative errno if initialization fails.
 */
static int lod_sub_init_llogs(const struct lu_env *env, struct lod_device *lod)
{
	struct lu_tgt_desc *mdt;
	int rc;

	ENTRY;

	/*
	 * llog must be setup after LOD is initialized, because llog
	 * initialization include FLD lookup
	 */
	LASSERT(lod->lod_initialized);

	/* Init the llog in its own stack */
	rc = lod_sub_init_llog(env, lod, lod->lod_child);
	if (rc < 0)
		RETURN(rc);

	lod_foreach_mdt(lod, mdt) {
		rc = lod_sub_init_llog(env, lod, mdt->ltd_tgt);
		if (rc != 0)
			break;
	}

	RETURN(rc);
}

/**
 * Implementation of lu_device_operations::ldo_prepare() for LOD
 *
 * see include/lu_object.h for the details.
 */
static int lod_prepare(const struct lu_env *env, struct lu_device *pdev,
		       struct lu_device *cdev)
{
	struct lod_device *lod = lu2lod_dev(cdev);
	struct lu_device *next = &lod->lod_child->dd_lu_dev;
	struct lu_fid *fid = &lod_env_info(env)->lti_fid;
	int rc;
	struct dt_object *root;
	struct dt_object *dto;
	u32 index;

	ENTRY;

	rc = next->ld_ops->ldo_prepare(env, pdev, next);
	if (rc != 0) {
		CERROR("%s: prepare bottom error: rc = %d\n",
		       lod2obd(lod)->obd_name, rc);
		RETURN(rc);
	}

	lod->lod_initialized = 1;

	rc = dt_root_get(env, lod->lod_child, fid);
	if (rc < 0)
		RETURN(rc);

	root = dt_locate(env, lod->lod_child, fid);
	if (IS_ERR(root))
		RETURN(PTR_ERR(root));

	/* Create update log object */
	index = lu_site2seq(lod2lu_dev(lod)->ld_site)->ss_node_id;
	lu_update_log_fid(fid, index);

	dto = local_file_find_or_create_with_fid(env, lod->lod_child,
						 fid, root,
						 lod_update_log_name,
						 S_IFREG | 0644);
	if (IS_ERR(dto))
		GOTO(out_put, rc = PTR_ERR(dto));

	dt_object_put(env, dto);

	/* Create update log dir */
	lu_update_log_dir_fid(fid, index);
	dto = local_file_find_or_create_with_fid(env, lod->lod_child,
						 fid, root,
						 lod_update_log_dir_name,
						 S_IFDIR | 0644);
	if (IS_ERR(dto))
		GOTO(out_put, rc = PTR_ERR(dto));

	dt_object_put(env, dto);

	rc = lod_prepare_distribute_txn(env, lod);
	if (rc != 0)
		GOTO(out_put, rc);

	rc = lod_sub_init_llogs(env, lod);
	if (rc != 0)
		GOTO(out_put, rc);

out_put:
	dt_object_put(env, root);

	RETURN(rc);
}

/**
 * Implementation of lu_device_operations::ldo_fid_alloc() for LOD
 *
 * Find corresponding device by passed parent and name, and allocate FID from
 * there.
 *
 * see include/lu_object.h for the details.
 */
static int lod_fid_alloc(const struct lu_env *env, struct lu_device *d,
			 struct lu_fid *fid, struct lu_object *parent,
			 const struct lu_name *name)
{
	struct lod_device *lod = lu2lod_dev(d);
	struct lod_object *lo = lu2lod_obj(parent);
	struct dt_device *next;
	int rc;

	ENTRY;

	/* if @parent is remote, we don't know whether its layout was changed,
	 * always reload layout.
	 */
	if (lu_object_remote(parent))
		lod_striping_free(env, lo);

	rc = lod_striping_load(env, lo);
	if (rc)
		RETURN(rc);

	if (lo->ldo_dir_stripe_count > 0 && name) {
		struct dt_object *stripe;
		int idx;

		idx = __lmv_name_to_stripe_index(lo->ldo_dir_hash_type,
						 lo->ldo_dir_stripe_count,
						 lo->ldo_dir_migrate_hash,
						 lo->ldo_dir_migrate_offset,
						 name->ln_name,
						 name->ln_namelen, true);
		if (idx < 0)
			RETURN(idx);

		stripe = lo->ldo_stripe[idx];
		if (!stripe || !dt_object_exists(stripe))
			RETURN(-ENODEV);

		next = lu2dt_dev(stripe->do_lu.lo_dev);
	} else {
		next = lod->lod_child;
	}

	rc = dt_fid_alloc(env, next, fid, parent, name);

	RETURN(rc);
}

const struct lu_device_operations lod_lu_ops = {
	.ldo_object_alloc	= lod_object_alloc,
	.ldo_process_config	= lod_process_config,
	.ldo_recovery_complete	= lod_recovery_complete,
	.ldo_prepare		= lod_prepare,
	.ldo_fid_alloc		= lod_fid_alloc,
};

/**
 * Implementation of dt_device_operations::dt_root_get() for LOD
 *
 * see include/dt_object.h for the details.
 */
static int lod_root_get(const struct lu_env *env,
			struct dt_device *dev, struct lu_fid *f)
{
	return dt_root_get(env, dt2lod_dev(dev)->lod_child, f);
}

static void lod_statfs_sum(struct obd_statfs *sfs,
			     struct obd_statfs *ost_sfs, int *bs)
{
	while (ost_sfs->os_bsize < *bs) {
		*bs >>= 1;
		sfs->os_bsize >>= 1;
		sfs->os_bavail <<= 1;
		sfs->os_blocks <<= 1;
		sfs->os_bfree <<= 1;
		sfs->os_granted <<= 1;
	}
	while (ost_sfs->os_bsize > *bs) {
		ost_sfs->os_bsize >>= 1;
		ost_sfs->os_bavail <<= 1;
		ost_sfs->os_blocks <<= 1;
		ost_sfs->os_bfree <<= 1;
		ost_sfs->os_granted <<= 1;
	}
	sfs->os_bavail += ost_sfs->os_bavail;
	sfs->os_blocks += ost_sfs->os_blocks;
	sfs->os_bfree += ost_sfs->os_bfree;
	sfs->os_granted += ost_sfs->os_granted;
}

/**
 * Implementation of dt_device_operations::dt_statfs() for LOD
 *
 * see include/dt_object.h for the details.
 */
static int lod_statfs(const struct lu_env *env, struct dt_device *dev,
		      struct obd_statfs *sfs, struct obd_statfs_info *info)
{
	struct lod_device *lod = dt2lod_dev(dev);
	struct lu_tgt_desc *tgt;
	struct obd_statfs ost_sfs;
	u64 ost_files = 0;
	u64 ost_ffree = 0;
	int rc, bs;

	rc = dt_statfs(env, dt2lod_dev(dev)->lod_child, sfs);
	if (rc)
		GOTO(out, rc);

	bs = sfs->os_bsize;

	sfs->os_bavail = 0;
	sfs->os_blocks = 0;
	sfs->os_bfree = 0;
	sfs->os_granted = 0;

	lod_getref(&lod->lod_mdt_descs);
	lod_foreach_mdt(lod, tgt) {
		rc = dt_statfs(env, tgt->ltd_tgt, &ost_sfs);
		/* ignore errors */
		if (rc)
			continue;
		sfs->os_files += ost_sfs.os_files;
		sfs->os_ffree += ost_sfs.os_ffree;
		lod_statfs_sum(sfs, &ost_sfs, &bs);
	}
	lod_putref(lod, &lod->lod_mdt_descs);

	/*
	 * at some point we can check whether DoM is enabled and
	 * decide how to account MDT space. for simplicity let's
	 * just fallback to pre-DoM policy if any OST is alive
	 */
	lod_getref(&lod->lod_ost_descs);
	lod_foreach_ost(lod, tgt) {
		rc = dt_statfs(env, tgt->ltd_tgt, &ost_sfs);
		/* ignore errors */
		if (rc || ost_sfs.os_bsize == 0)
			continue;
		if (!ost_files) {
			/*
			 * if only MDTs with DoM then report only MDT blocks,
			 * otherwise show only OST blocks, and DoM is "free"
			 */
			sfs->os_bavail = 0;
			sfs->os_blocks = 0;
			sfs->os_bfree = 0;
			sfs->os_granted = 0;
		}
		ost_files += ost_sfs.os_files;
		ost_ffree += ost_sfs.os_ffree;
		ost_sfs.os_bavail += ost_sfs.os_granted;
		lod_statfs_sum(sfs, &ost_sfs, &bs);
		LASSERTF(bs == ost_sfs.os_bsize, "%d != %d\n",
			(int)sfs->os_bsize, (int)ost_sfs.os_bsize);
	}
	lod_putref(lod, &lod->lod_ost_descs);
	sfs->os_state |= OS_STATFS_SUM;

	/* If we have _some_ OSTs, but don't have as many free objects on the
	 * OSTs as inodes on the MDTs, reduce the reported number of inodes
	 * to compensate, so that the "inodes in use" number is correct.
	 * This should be kept in sync with ll_statfs_internal().
	 */
	if (ost_files && ost_ffree < sfs->os_ffree) {
		sfs->os_files = (sfs->os_files - sfs->os_ffree) + ost_ffree;
		sfs->os_ffree = ost_ffree;
	}

	/* a single successful statfs should be enough */
	rc = 0;

out:
	RETURN(rc);
}

/**
 * Implementation of dt_device_operations::dt_trans_create() for LOD
 *
 * Creates a transaction using local (to this node) OSD.
 *
 * see include/dt_object.h for the details.
 */
static struct thandle *lod_trans_create(const struct lu_env *env,
					struct dt_device *dt)
{
	struct thandle *th;

	th = top_trans_create(env, dt2lod_dev(dt)->lod_child);
	if (IS_ERR(th))
		return th;

	th->th_dev = dt;

	return th;
}

/**
 * Implementation of dt_device_operations::dt_trans_start() for LOD
 *
 * Starts the set of local transactions using the targets involved
 * in declare phase. Initial support for the distributed transactions.
 *
 * see include/dt_object.h for the details.
 */
static int lod_trans_start(const struct lu_env *env, struct dt_device *dt,
			   struct thandle *th)
{
	return top_trans_start(env, dt2lod_dev(dt)->lod_child, th);
}

static int lod_trans_cb_add(struct thandle *th,
			    struct dt_txn_commit_cb *dcb)
{
	struct top_thandle	*top_th = container_of(th, struct top_thandle,
						       tt_super);
	return dt_trans_cb_add(top_th->tt_master_sub_thandle, dcb);
}

/**
 * add noop update to the update records
 *
 * Add noop updates to the update records, which is only used in
 * test right now.
 *
 * \param[in] env	execution environment
 * \param[in] dt	dt device of lod
 * \param[in] th	thandle
 * \param[in] count	the count of update records to be added.
 *
 * \retval		0 if adding succeeds.
 * \retval		negative errno if adding fails.
 */
static int lod_add_noop_records(const struct lu_env *env,
				struct dt_device *dt, struct thandle *th,
				int count)
{
	struct top_thandle *top_th;
	struct lu_fid *fid = &lod_env_info(env)->lti_fid;
	int i;
	int rc = 0;

	top_th = container_of(th, struct top_thandle, tt_super);
	if (!top_th->tt_multiple_thandle)
		return 0;

	fid_zero(fid);
	for (i = 0; i < count; i++) {
		rc = update_record_pack(noop, th, fid);
		if (rc < 0)
			return rc;
	}
	return rc;
}

/**
 * Implementation of dt_device_operations::dt_trans_stop() for LOD
 *
 * Stops the set of local transactions using the targets involved
 * in declare phase. Initial support for the distributed transactions.
 *
 * see include/dt_object.h for the details.
 */
static int lod_trans_stop(const struct lu_env *env, struct dt_device *dt,
			  struct thandle *th)
{
	if (OBD_FAIL_CHECK(OBD_FAIL_SPLIT_UPDATE_REC)) {
		int rc;

		rc = lod_add_noop_records(env, dt, th, 5000);
		if (rc < 0)
			RETURN(rc);
	}
	return top_trans_stop(env, dt2lod_dev(dt)->lod_child, th);
}

/**
 * Implementation of dt_device_operations::dt_conf_get() for LOD
 *
 * Currently returns the configuration provided by the local OSD.
 *
 * see include/dt_object.h for the details.
 */
static void lod_conf_get(const struct lu_env *env,
			 const struct dt_device *dev,
			 struct dt_device_param *param)
{
	dt_conf_get(env, dt2lod_dev((struct dt_device *)dev)->lod_child, param);
}

/**
 * Implementation of dt_device_operations::dt_sync() for LOD
 *
 * Syncs all known OST targets. Very very expensive and used
 * rarely by LFSCK now. Should not be used in general.
 *
 * see include/dt_object.h for the details.
 */
static int lod_sync(const struct lu_env *env, struct dt_device *dev)
{
	struct lod_device *lod = dt2lod_dev(dev);
	struct lu_tgt_desc *tgt;
	int rc = 0;

	ENTRY;

	lod_getref(&lod->lod_ost_descs);
	lod_foreach_ost(lod, tgt) {
		if (!tgt->ltd_active)
			continue;
		rc = dt_sync(env, tgt->ltd_tgt);
		if (rc) {
			if (rc != -ENOTCONN) {
				CERROR("%s: can't sync ost %u: rc = %d\n",
				       lod2obd(lod)->obd_name, tgt->ltd_index,
				       rc);
				break;
			}
			rc = 0;
		}
	}
	lod_putref(lod, &lod->lod_ost_descs);

	if (rc)
		RETURN(rc);

	lod_getref(&lod->lod_mdt_descs);
	lod_foreach_mdt(lod, tgt) {
		if (!tgt->ltd_active)
			continue;
		rc = dt_sync(env, tgt->ltd_tgt);
		if (rc) {
			if (rc != -ENOTCONN) {
				CERROR("%s: can't sync mdt %u: rc = %d\n",
				       lod2obd(lod)->obd_name, tgt->ltd_index,
				       rc);
				break;
			}
			rc = 0;
		}
	}
	lod_putref(lod, &lod->lod_mdt_descs);

	if (rc == 0)
		rc = dt_sync(env, lod->lod_child);

	RETURN(rc);
}

/**
 * Implementation of dt_device_operations::dt_ro() for LOD
 *
 * Turns local OSD read-only, used for the testing only.
 *
 * see include/dt_object.h for the details.
 */
static int lod_ro(const struct lu_env *env, struct dt_device *dev)
{
	return dt_ro(env, dt2lod_dev(dev)->lod_child);
}

/**
 * Implementation of dt_device_operations::dt_commit_async() for LOD
 *
 * Asks local OSD to commit sooner.
 *
 * see include/dt_object.h for the details.
 */
static int lod_commit_async(const struct lu_env *env, struct dt_device *dev)
{
	return dt_commit_async(env, dt2lod_dev(dev)->lod_child);
}

static const struct dt_device_operations lod_dt_ops = {
	.dt_root_get         = lod_root_get,
	.dt_statfs           = lod_statfs,
	.dt_trans_create     = lod_trans_create,
	.dt_trans_start      = lod_trans_start,
	.dt_trans_stop       = lod_trans_stop,
	.dt_conf_get         = lod_conf_get,
	.dt_sync             = lod_sync,
	.dt_ro               = lod_ro,
	.dt_commit_async     = lod_commit_async,
	.dt_trans_cb_add     = lod_trans_cb_add,
};

/**
 * Connect to a local OSD.
 *
 * Used to connect to the local OSD at mount. OSD name is taken from the
 * configuration command passed. This connection is used to identify LU
 * site and pin the OSD from early removal.
 *
 * \param[in] env		LU environment provided by the caller
 * \param[in] lod		lod device
 * \param[in] cfg		configuration command to apply
 *
 * \retval 0			on success
 * \retval negative		negated errno on error
 **/
static int lod_connect_to_osd(const struct lu_env *env, struct lod_device *lod,
			      struct lustre_cfg *cfg)
{
	struct obd_connect_data *data = NULL;
	struct obd_device *obd;
	char *nextdev = NULL, *p, *s;
	int rc, len = 0;

	ENTRY;

	LASSERT(cfg);
	LASSERT(lod->lod_child_exp == NULL);

	/*
	 * compatibility hack: we still use old config logs
	 * which specify LOV, but we need to learn underlying
	 * OSD device, which is supposed to be:
	 *  <fsname>-MDTxxxx-osd
	 *
	 * 2.x MGS generates lines like the following:
	 *   #03 (176)lov_setup 0:lustre-MDT0000-mdtlov  1:(struct lov_desc)
	 * 1.8 MGS generates lines like the following:
	 *   #03 (168)lov_setup 0:lustre-mdtlov  1:(struct lov_desc)
	 *
	 * we use "-MDT" to differentiate 2.x from 1.8
	 */
	p = lustre_cfg_string(cfg, 0);
	if (p && strstr(p, "-mdtlov")) {
		len = strlen(p) + 6;
		OBD_ALLOC(nextdev, len);
		if (!nextdev)
			GOTO(out, rc = -ENOMEM);

		strcpy(nextdev, p);
		s = strstr(nextdev, "-mdtlov");
		if (unlikely(!s)) {
			CERROR("%s: unable to parse device name: rc = %d\n",
			       lustre_cfg_string(cfg, 0), -EINVAL);
			GOTO(out, rc = -EINVAL);
		}

		if (strstr(nextdev, "-MDT")) {
			/* 2.x config */
			strcpy(s, "-osd");
		} else {
			/* 1.8 config */
			strcpy(s, "-MDT0000-osd");
		}
	} else {
		CERROR("%s: unable to parse device name: rc = %d\n",
		       lustre_cfg_string(cfg, 0), -EINVAL);
		GOTO(out, rc = -EINVAL);
	}

	OBD_ALLOC_PTR(data);
	if (!data)
		GOTO(out, rc = -ENOMEM);

	obd = class_name2obd(nextdev);
	if (!obd) {
		CERROR("%s: can not locate next device: rc = %d\n",
		       nextdev, -ENOTCONN);
		GOTO(out, rc = -ENOTCONN);
	}

	data->ocd_connect_flags = OBD_CONNECT_VERSION;
	data->ocd_version = LUSTRE_VERSION_CODE;

	rc = obd_connect(env, &lod->lod_child_exp, obd, &obd->obd_uuid,
			 data, NULL);
	if (rc) {
		CERROR("%s: cannot connect to next dev: rc = %d\n",
		       nextdev, rc);
		GOTO(out, rc);
	}

	lod->lod_dt_dev.dd_lu_dev.ld_site =
		lod->lod_child_exp->exp_obd->obd_lu_dev->ld_site;
	LASSERT(lod->lod_dt_dev.dd_lu_dev.ld_site);
	lod->lod_child = lu2dt_dev(lod->lod_child_exp->exp_obd->obd_lu_dev);

out:
	if (data)
		OBD_FREE_PTR(data);
	if (nextdev)
		OBD_FREE(nextdev, len);
	RETURN(rc);
}

static int lod_lsfs_init(const struct lu_env *env, struct lod_device *d)
{
	struct obd_statfs sfs;
	int rc;

	rc = dt_statfs(env, d->lod_child, &sfs);
	if (rc) {
		CDEBUG(D_LAYOUT, "%s: failed to get OSD statfs, rc = %d\n",
		       lod2obd(d)->obd_name, rc);
		return rc;
	}

	/* udpate local OSD cached statfs data */
	spin_lock_init(&d->lod_lsfs_lock);
	d->lod_lsfs_age = ktime_get_seconds();
	d->lod_lsfs_total_mb = (sfs.os_blocks * sfs.os_bsize) >> 20;
	d->lod_lsfs_free_mb = (sfs.os_bfree * sfs.os_bsize) >> 20;
	return 0;
}

/**
 * Initialize LOD device at setup.
 *
 * Initializes the given LOD device using the original configuration command.
 * The function initiates a connection to the local OSD and initializes few
 * internal structures like pools, target tables, etc.
 *
 * \param[in] env		LU environment provided by the caller
 * \param[in] lod		lod device
 * \param[in] ldt		not used
 * \param[in] cfg		configuration command
 *
 * \retval 0			on success
 * \retval negative		negated errno on error
 **/
static int lod_init0(const struct lu_env *env, struct lod_device *lod,
		     struct lu_device_type *ldt, struct lustre_cfg *cfg)
{
	struct dt_device_param ddp;
	struct obd_device *obd;
	int rc;

	ENTRY;

	obd = class_name2obd(lustre_cfg_string(cfg, 0));
	if (!obd) {
		rc = -ENODEV;
		CERROR("Cannot find obd with name '%s': rc = %d\n",
		       lustre_cfg_string(cfg, 0), rc);
		RETURN(rc);
	}

	obd->obd_lu_dev = &lod->lod_dt_dev.dd_lu_dev;
	lod->lod_dt_dev.dd_lu_dev.ld_obd = obd;
	lod->lod_dt_dev.dd_lu_dev.ld_ops = &lod_lu_ops;
	lod->lod_dt_dev.dd_ops = &lod_dt_ops;

	rc = lod_connect_to_osd(env, lod, cfg);
	if (rc)
		RETURN(rc);

	dt_conf_get(env, &lod->lod_dt_dev, &ddp);
	lod->lod_osd_max_easize = ddp.ddp_max_ea_size;
	lod->lod_dom_stripesize_max_kb = (1ULL << 10); /* 1Mb is default */

	/* initialize local statfs cached values */
	rc = lod_lsfs_init(env, lod);
	if (rc)
		GOTO(out_disconnect, rc);

	/* default threshold as half of total space, in MiB */
	lod->lod_dom_threshold_free_mb = lod->lod_lsfs_total_mb / 2;
	/* set default DoM stripe size based on free space amount */
	lod_dom_stripesize_recalc(lod);

	/* setup obd to be used with old lov code */
	rc = lod_pools_init(lod, cfg);
	if (rc)
		GOTO(out_disconnect, rc);

	rc = lod_procfs_init(lod);
	if (rc)
		GOTO(out_pools, rc);

	spin_lock_init(&lod->lod_lock);
	spin_lock_init(&lod->lod_connects_lock);
	lu_tgt_descs_init(&lod->lod_mdt_descs, true);
	lu_tgt_descs_init(&lod->lod_ost_descs, false);
	lu_qos_rr_init(&lod->lod_mdt_descs.ltd_qos.lq_rr);
	lu_qos_rr_init(&lod->lod_ost_descs.ltd_qos.lq_rr);

	RETURN(0);

out_pools:
	lod_pools_fini(lod);
out_disconnect:
	obd_disconnect(lod->lod_child_exp);
	RETURN(rc);
}

/**
 * Implementation of lu_device_type_operations::ldto_device_free() for LOD
 *
 * Releases the memory allocated for LOD device.
 *
 * see include/lu_object.h for the details.
 */
static struct lu_device *lod_device_free(const struct lu_env *env,
					 struct lu_device *lu)
{
	struct lod_device *lod = lu2lod_dev(lu);
	struct lu_device  *next = &lod->lod_child->dd_lu_dev;

	ENTRY;

	if (atomic_read(&lu->ld_site->ls_obj_hash.nelems)) {
		lu_site_print(env, lu->ld_site, &lu->ld_ref, D_ERROR,
			      lu_cdebug_printer);
	}
	LASSERTF(atomic_read(&lu->ld_ref) == 0, "lu is %p\n", lu);
	dt_device_fini(&lod->lod_dt_dev);
	OBD_FREE_PTR(lod);
	RETURN(next);
}

/**
 * Implementation of lu_device_type_operations::ldto_device_alloc() for LOD
 *
 * Allocates LOD device and calls the helpers to initialize it.
 *
 * see include/lu_object.h for the details.
 */
static struct lu_device *lod_device_alloc(const struct lu_env *env,
					  struct lu_device_type *type,
					  struct lustre_cfg *lcfg)
{
	struct lod_device *lod;
	struct lu_device *lu_dev;

	OBD_ALLOC_PTR(lod);
	if (!lod) {
		lu_dev = ERR_PTR(-ENOMEM);
	} else {
		int rc;

		lu_dev = lod2lu_dev(lod);
		dt_device_init(&lod->lod_dt_dev, type);
		rc = lod_init0(env, lod, type, lcfg);
		if (rc != 0) {
			lod_device_free(env, lu_dev);
			lu_dev = ERR_PTR(rc);
		}
	}

	return lu_dev;
}

static void lod_avoid_guide_fini(struct lod_avoid_guide *lag)
{
	if (lag->lag_oss_avoid_array)
		OBD_FREE_PTR_ARRAY(lag->lag_oss_avoid_array,
				   lag->lag_oaa_size);
	bitmap_free(lag->lag_ost_avoid_bitmap);
}

/**
 * Implementation of lu_device_type_operations::ldto_device_fini() for LOD
 *
 * Releases the internal resources used by LOD device.
 *
 * see include/lu_object.h for the details.
 */
static struct lu_device *lod_device_fini(const struct lu_env *env,
					 struct lu_device *d)
{
	struct lod_device *lod = lu2lod_dev(d);
	int rc;

	ENTRY;

	lod_pools_fini(lod);

	lod_procfs_fini(lod);

	rc = lod_fini_tgt(env, lod, &lod->lod_ost_descs);
	if (rc)
		CERROR("%s: can not fini ost descriptors: rc =  %d\n",
			lod2obd(lod)->obd_name, rc);

	rc = lod_fini_tgt(env, lod, &lod->lod_mdt_descs);
	if (rc)
		CERROR("%s: can not fini mdt descriptors: rc =  %d\n",
			lod2obd(lod)->obd_name, rc);

	RETURN(NULL);
}

/**
 * Implementation of obd_ops::o_connect() for LOD
 *
 * Used to track all the users of this specific LOD device,
 * so the device stays up until the last user disconnected.
 *
 * \param[in] env		LU environment provided by the caller
 * \param[out] exp		export the caller will be using to access LOD
 * \param[in] obd		OBD device representing LOD device
 * \param[in] cluuid		unique identifier of the caller
 * \param[in] data		not used
 * \param[in] localdata		not used
 *
 * \retval 0			on success
 * \retval negative		negated errno on error
 **/
static int lod_obd_connect(const struct lu_env *env, struct obd_export **exp,
			   struct obd_device *obd, struct obd_uuid *cluuid,
			   struct obd_connect_data *data, void *localdata)
{
	struct lod_device *lod = lu2lod_dev(obd->obd_lu_dev);
	struct lustre_handle conn;
	int rc;

	ENTRY;

	CDEBUG(D_CONFIG, "connect #%d\n", lod->lod_connects);

	rc = class_connect(&conn, obd, cluuid);
	if (rc)
		RETURN(rc);

	*exp = class_conn2export(&conn);

	spin_lock(&lod->lod_connects_lock);
	lod->lod_connects++;
	/* at the moment we expect the only user */
	LASSERT(lod->lod_connects == 1);
	spin_unlock(&lod->lod_connects_lock);

	RETURN(0);
}

/**
 *
 * Implementation of obd_ops::o_disconnect() for LOD
 *
 * When the caller doesn't need to use this LOD instance, it calls
 * obd_disconnect() and LOD releases corresponding export/reference count.
 * Once all the users gone, LOD device is released.
 *
 * \param[in] exp		export provided to the caller in obd_connect()
 *
 * \retval 0			on success
 * \retval negative		negated errno on error
 **/
static int lod_obd_disconnect(struct obd_export *exp)
{
	struct obd_device *obd = exp->exp_obd;
	struct lod_device *lod = lu2lod_dev(obd->obd_lu_dev);
	int rc, release = 0;

	ENTRY;

	/* Only disconnect the underlying layers on the final disconnect. */
	spin_lock(&lod->lod_connects_lock);
	lod->lod_connects--;
	if (lod->lod_connects != 0) {
		/* why should there be more than 1 connect? */
		spin_unlock(&lod->lod_connects_lock);
		CERROR("%s: disconnect #%d\n", exp->exp_obd->obd_name,
		       lod->lod_connects);
		goto out;
	}
	spin_unlock(&lod->lod_connects_lock);

	/* the last user of lod has gone, let's release the device */
	release = 1;

out:
	rc = class_disconnect(exp); /* bz 9811 */

	if (rc == 0 && release)
		class_manual_cleanup(obd);
	RETURN(rc);
}

LU_KEY_INIT(lod, struct lod_thread_info);

static void lod_key_fini(const struct lu_context *ctx,
		struct lu_context_key *key, void *data)
{
	struct lod_thread_info *info = data;
	struct lod_layout_component *lds =
				info->lti_def_striping.lds_def_comp_entries;

	/*
	 * allocated in lod_get_lov_ea
	 * XXX: this is overload, a tread may have such store but used only
	 * once. Probably better would be pool of such stores per LOD.
	 */
	if (info->lti_ea_store) {
		OBD_FREE_LARGE(info->lti_ea_store, info->lti_ea_store_size);
		info->lti_ea_store = NULL;
		info->lti_ea_store_size = 0;
	}
	lu_buf_free(&info->lti_linkea_buf);

	if (lds)
		lod_free_def_comp_entries(&info->lti_def_striping);

	if (info->lti_comp_size > 0)
		OBD_FREE_PTR_ARRAY(info->lti_comp_idx,
				   info->lti_comp_size);

	lod_avoid_guide_fini(&info->lti_avoid);

	OBD_FREE_PTR(info);
}

/* context key: lod_thread_key */
LU_CONTEXT_KEY_DEFINE(lod, LCT_MD_THREAD);

LU_TYPE_INIT_FINI(lod, &lod_thread_key);

static const struct lu_device_type_operations lod_device_type_ops = {
	.ldto_init		= lod_type_init,
	.ldto_fini		= lod_type_fini,

	.ldto_start		= lod_type_start,
	.ldto_stop		= lod_type_stop,

	.ldto_device_alloc	= lod_device_alloc,
	.ldto_device_free	= lod_device_free,

	.ldto_device_fini	= lod_device_fini
};

static struct lu_device_type lod_device_type = {
	.ldt_tags     = LU_DEVICE_DT,
	.ldt_name     = LUSTRE_LOD_NAME,
	.ldt_ops      = &lod_device_type_ops,
	.ldt_ctx_tags = LCT_MD_THREAD,
};

/**
 * Implementation of obd_ops::o_get_info() for LOD
 *
 * Currently, there is only one supported key: KEY_OSP_CONNECTED , to provide
 * the caller binary status whether LOD has seen connection to any OST target.
 * It will also check if the MDT update log context being initialized (if
 * needed).
 *
 * \param[in] env		LU environment provided by the caller
 * \param[in] exp		export of the caller
 * \param[in] keylen		len of the key
 * \param[in] key		the key
 * \param[in] vallen		not used
 * \param[in] val		not used
 *
 * \retval			0 if a connection was seen
 * \retval			-EAGAIN if LOD isn't running yet or no
 *				connection has been seen yet
 * \retval			-EINVAL if not supported key is requested
 **/
static int lod_obd_get_info(const struct lu_env *env, struct obd_export *exp,
			    u32 keylen, void *key, u32 *vallen, void *val)
{
	int rc = -EINVAL;

	if (KEY_IS(KEY_OSP_CONNECTED)) {
		struct obd_device *obd = exp->exp_obd;
		struct lod_device *d;
		struct lod_tgt_desc *tgt;
		int rc = 1;

		if (!obd->obd_set_up || obd->obd_stopping)
			RETURN(-EAGAIN);

		d = lu2lod_dev(obd->obd_lu_dev);
		lod_getref(&d->lod_ost_descs);
		lod_foreach_ost(d, tgt) {
			rc = obd_get_info(env, tgt->ltd_exp, keylen, key,
					  vallen, val);
			/* one healthy device is enough */
			if (rc == 0)
				break;
		}
		lod_putref(d, &d->lod_ost_descs);

		lod_getref(&d->lod_mdt_descs);
		lod_foreach_mdt(d, tgt) {
			struct llog_ctxt *ctxt;

			if (!tgt->ltd_active)
				continue;

			ctxt = llog_get_context(tgt->ltd_tgt->dd_lu_dev.ld_obd,
						LLOG_UPDATELOG_ORIG_CTXT);
			if (!ctxt) {
				CDEBUG(D_INFO, "%s: %s is not ready.\n",
				       obd->obd_name,
				      tgt->ltd_tgt->dd_lu_dev.ld_obd->obd_name);
				rc = -EAGAIN;
				break;
			}
			if (!ctxt->loc_handle) {
				CDEBUG(D_INFO, "%s: %s is not ready.\n",
				       obd->obd_name,
				      tgt->ltd_tgt->dd_lu_dev.ld_obd->obd_name);
				rc = -EAGAIN;
				llog_ctxt_put(ctxt);
				break;
			}
			llog_ctxt_put(ctxt);
		}
		lod_putref(d, &d->lod_mdt_descs);

		RETURN(rc);
	}

	RETURN(rc);
}

static int lod_obd_set_info_async(const struct lu_env *env,
				  struct obd_export *exp,
				  u32 keylen, void *key,
				  u32 vallen, void *val,
				  struct ptlrpc_request_set *set)
{
	struct obd_device *obd = class_exp2obd(exp);
	struct lod_device *d;
	struct lod_tgt_desc *tgt;
	int no_set = 0;
	int rc = 0, rc2;

	ENTRY;

	if (!set) {
		no_set = 1;
		set = ptlrpc_prep_set();
		if (!set)
			RETURN(-ENOMEM);
	}

	d = lu2lod_dev(obd->obd_lu_dev);
	lod_getref(&d->lod_ost_descs);
	lod_foreach_ost(d, tgt) {
		if (!tgt->ltd_active)
			continue;

		rc2 = obd_set_info_async(env, tgt->ltd_exp, keylen, key,
					 vallen, val, set);
		if (rc2 != 0 && rc == 0)
			rc = rc2;
	}
	lod_putref(d, &d->lod_ost_descs);

	lod_getref(&d->lod_mdt_descs);
	lod_foreach_mdt(d, tgt) {
		if (!tgt->ltd_active)
			continue;
		rc2 = obd_set_info_async(env, tgt->ltd_exp, keylen, key,
					 vallen, val, set);
		if (rc2 != 0 && rc == 0)
			rc = rc2;
	}
	lod_putref(d, &d->lod_mdt_descs);


	if (no_set) {
		rc2 = ptlrpc_set_wait(env, set);
		if (rc2 == 0 && rc == 0)
			rc = rc2;
		ptlrpc_set_destroy(set);
	}
	RETURN(rc);
}


#define QMT0_DEV_NAME_LEN (LUSTRE_MAXFSNAME + sizeof("-QMT0000"))
static struct obd_device *obd_find_qmt0(char *obd_name)
{
	char qmt_name[QMT0_DEV_NAME_LEN];
	struct obd_device *qmt = NULL;

	if (!server_name2fsname(obd_name, qmt_name, NULL)) {
		strlcat(qmt_name, "-QMT0000", QMT0_DEV_NAME_LEN);
		qmt = class_name2obd(qmt_name);
	}

	return qmt;
}

static int lod_pool_new_q(struct obd_device *obd, char *poolname)
{
	int err = lod_pool_new(obd, poolname);

	if (!err) {
		obd = obd_find_qmt0(obd->obd_name);
		if (obd)
			obd_pool_new(obd, poolname);
	}

	return err;
}

static int lod_pool_remove_q(struct obd_device *obd, char *poolname,
			     char *ostname)
{
	int err = lod_pool_remove(obd, poolname, ostname);

	if (!err) {
		obd = obd_find_qmt0(obd->obd_name);
		if (obd)
			obd_pool_rem(obd, poolname, ostname);
	}

	return err;
}

static int lod_pool_add_q(struct obd_device *obd, char *poolname, char *ostname)
{
	int err = lod_pool_add(obd, poolname, ostname);

	if (!err) {
		obd = obd_find_qmt0(obd->obd_name);
		if (obd)
			obd_pool_add(obd, poolname, ostname);
	}

	return err;
}

static int lod_pool_del_q(struct obd_device *obd, char *poolname)
{
	int err = lod_pool_del(obd, poolname);

	if (!err) {
		obd = obd_find_qmt0(obd->obd_name);
		if (obd)
			obd_pool_del(obd, poolname);
	}

	return err;
}

static const struct obd_ops lod_obd_device_ops = {
	.o_owner        = THIS_MODULE,
	.o_connect      = lod_obd_connect,
	.o_disconnect   = lod_obd_disconnect,
	.o_get_info     = lod_obd_get_info,
	.o_set_info_async = lod_obd_set_info_async,
	.o_pool_new     = lod_pool_new_q,
	.o_pool_rem     = lod_pool_remove_q,
	.o_pool_add     = lod_pool_add_q,
	.o_pool_del     = lod_pool_del_q,
};

static int __init lod_init(void)
{
	struct obd_type *sym;
	int rc;

	rc = lu_kmem_init(lod_caches);
	if (rc)
		return rc;

	rc = class_register_type(&lod_obd_device_ops, NULL, true,
				 LUSTRE_LOD_NAME, &lod_device_type);
	if (rc) {
		lu_kmem_fini(lod_caches);
		return rc;
	}

	/* create "lov" entry for compatibility purposes */
	sym = class_add_symlinks(LUSTRE_LOV_NAME, true);
	if (IS_ERR(sym)) {
		rc = PTR_ERR(sym);
		/* does real "lov" already exist ? */
		if (rc == -EEXIST)
			rc = 0;
	}

	return rc;
}

static void __exit lod_exit(void)
{
	struct obd_type *sym = class_search_type(LUSTRE_LOV_NAME);

	/* if this was never fully initialized by the lov layer
	 * then we are responsible for freeing this obd_type
	 */
	if (sym) {
		/* final put if we manage this obd type */
		if (sym->typ_sym_filter)
			kobject_put(&sym->typ_kobj);
		/* put reference taken by class_search_type */
		kobject_put(&sym->typ_kobj);
	}

	class_unregister_type(LUSTRE_LOD_NAME);
	lu_kmem_fini(lod_caches);
}

MODULE_AUTHOR("OpenSFS, Inc. <http://www.lustre.org/>");
MODULE_DESCRIPTION("Lustre Logical Object Device ("LUSTRE_LOD_NAME")");
MODULE_VERSION(LUSTRE_VERSION_STRING);
MODULE_LICENSE("GPL");

module_init(lod_init);
module_exit(lod_exit);
