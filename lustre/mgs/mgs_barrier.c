/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License version 2 for more details.  A copy is
 * included in the COPYING file that accompanied this code.

 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2017, Intel Corporation.
 *
 * lustre/mgs/mgs_barrier.c
 *
 * Author: Fan, Yong <fan.yong@intel.com>
 */

#define DEBUG_SUBSYSTEM S_MGS
#define D_MGS D_CONFIG

#include <uapi/linux/lustre/lustre_ioctl.h>
#include <lustre_swab.h>
#include <uapi/linux/lustre/lustre_barrier_user.h>

#include "mgs_internal.h"

/**
 * Handle the barrier lock glimpse reply.
 *
 * The barrier lock glimpse reply contains the target MDT's index and
 * the barrier operation status on such MDT. With such infomation. If
 * the MDT given barrier status is the expected one, then set related
 * 'fsdb''s barrier bitmap; otherwise record the failure or status.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] req	pointer to the glimpse callback RPC request
 * \param[in] data	pointer the async glimpse callback data
 * \param[in] rc	the glimpse callback RPC return value
 *
 * \retval		0 for success
 * \retval		negative error number on failure
 */
static int mgs_barrier_gl_interpret_reply(const struct lu_env *env,
					  struct ptlrpc_request *req,
					  void *data, int rc)
{
	struct ldlm_cb_async_args *ca = data;
	struct fs_db *fsdb = ca->ca_set_arg->gl_interpret_data;
	struct barrier_lvb *lvb;
	ENTRY;

	if (rc) {
		if (rc == -ENODEV) {
			/* The lock is useless, cancel it. */
			ldlm_lock_cancel(ca->ca_lock);
			rc = 0;
		}

		GOTO(out, rc);
	}

	lvb = req_capsule_server_swab_get(&req->rq_pill, &RMF_DLM_LVB,
					  lustre_swab_barrier_lvb);
	if (!lvb)
		GOTO(out, rc = -EPROTO);

	if (lvb->lvb_status == fsdb->fsdb_barrier_expected) {
		if (unlikely(lvb->lvb_index > INDEX_MAP_SIZE))
			rc = -EINVAL;
		else
			set_bit(lvb->lvb_index, fsdb->fsdb_barrier_map);
	} else if (likely(!test_bit(lvb->lvb_index, fsdb->fsdb_barrier_map))) {
		fsdb->fsdb_barrier_result = lvb->lvb_status;
	}

	GOTO(out, rc);

out:
	if (rc)
		fsdb->fsdb_barrier_result = rc;

	return rc;
}

/**
 * Send glimpse callback to the barrier locks holders.
 *
 * The glimpse callback takes the current barrier status. The barrier locks
 * holders (on the MDTs) will take related barrier actions according to the
 * given barrier status, then return their local barrier status.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] mgs	pointer to the MGS device
 * \param[in] fsdb	pointer the barrier 'fsdb'
 * \param[in] timeout	indicate when the barrier will be expired
 * \param[in] expected	the expected barrier status on remote servers (MDTs)
 *
 * \retval		positive number for unexpected barrier status
 * \retval		0 for success
 * \retval		negative error number on failure
 */
static int mgs_barrier_glimpse_lock(const struct lu_env *env,
				    struct mgs_device *mgs,
				    struct fs_db *fsdb,
				    __u32 timeout, __u32 expected)
{
	union ldlm_gl_desc *desc = &mgs_env_info(env)->mgi_gl_desc;
	struct ldlm_res_id res_id;
	struct ldlm_resource *res;
	struct ldlm_glimpse_work *work;
	struct ldlm_glimpse_work *tmp;
	LIST_HEAD(gl_list);
	struct list_head *pos;
	int i;
	int rc;
	ENTRY;

	LASSERT(fsdb->fsdb_mdt_count > 0);

	rc = mgc_logname2resid(fsdb->fsdb_name, &res_id, MGS_CFG_T_BARRIER);
	if (rc)
		RETURN(rc);

	res = ldlm_resource_get(mgs->mgs_obd->obd_namespace, NULL, &res_id,
				LDLM_PLAIN, 0);
	if (IS_ERR(res))
		RETURN(PTR_ERR(res));

	fsdb->fsdb_barrier_result = 0;
	fsdb->fsdb_barrier_expected = expected;
	desc->barrier_desc.lgbd_status = fsdb->fsdb_barrier_status;
	desc->barrier_desc.lgbd_timeout = timeout;

again:
	list_for_each_entry(work, &gl_list, gl_list) {
		if (!work->gl_lock)
			break;

		LDLM_LOCK_RELEASE(work->gl_lock);
		work->gl_lock = NULL;
	}

	/* It is not big issue to alloc more work item than needed. */
	for (i = 0; i < fsdb->fsdb_mdt_count; i++) {
		OBD_ALLOC_PTR(work);
		if (!work)
			GOTO(out, rc = -ENOMEM);

		list_add_tail(&work->gl_list, &gl_list);
	}

	work = list_entry(gl_list.next, struct ldlm_glimpse_work, gl_list);

	lock_res(res);
	list_for_each(pos, &res->lr_granted) {
		struct ldlm_lock *lock = list_entry(pos, struct ldlm_lock,
						    l_res_link);

		work->gl_lock = LDLM_LOCK_GET(lock);
		work->gl_flags = 0;
		work->gl_desc = desc;
		work->gl_interpret_reply = mgs_barrier_gl_interpret_reply;
		work->gl_interpret_data = fsdb;

		if (unlikely(work->gl_list.next == &gl_list)) {
			if (likely(pos->next == &res->lr_granted))
				break;

			unlock_res(res);
			/* The granted locks are more than the MDTs count. */
			goto again;
		}

		work = list_entry(work->gl_list.next, struct ldlm_glimpse_work,
				  gl_list);
	}
	unlock_res(res);

	/* The MDTs count may be more than the granted locks. */
	list_for_each_entry_safe_reverse(work, tmp, &gl_list, gl_list) {
		if (work->gl_lock)
			break;

		list_del(&work->gl_list);
		OBD_FREE_PTR(work);
	}

	if (!list_empty(&gl_list))
		rc = ldlm_glimpse_locks(res, &gl_list);
	else
		rc = -ENODEV;

	GOTO(out, rc);

out:
	list_for_each_entry_safe(work, tmp, &gl_list, gl_list) {
		list_del(&work->gl_list);
		if (work->gl_lock)
			LDLM_LOCK_RELEASE(work->gl_lock);
		OBD_FREE_PTR(work);
	}

	ldlm_resource_putref(res);
	if (!rc)
		rc = fsdb->fsdb_barrier_result;

	return rc;
}

static void mgs_barrier_bitmap_setup(struct mgs_device *mgs,
				     struct fs_db *b_fsdb,
				     const char *name)
{
	struct fs_db *c_fsdb;

	c_fsdb = mgs_find_fsdb(mgs, name);
	if (likely(c_fsdb)) {
		memcpy(b_fsdb->fsdb_mdt_index_map,
		       c_fsdb->fsdb_mdt_index_map, INDEX_MAP_SIZE);
		b_fsdb->fsdb_mdt_count = c_fsdb->fsdb_mdt_count;
		mgs_put_fsdb(mgs, c_fsdb);
	}
}

static bool mgs_barrier_done(struct fs_db *fsdb)
{
	int i;

	for (i = 0; i < INDEX_MAP_SIZE * 8; i++) {
		if (test_bit(i, fsdb->fsdb_mdt_index_map) &&
		    !test_bit(i, fsdb->fsdb_barrier_map))
			return false;
	}

	return true;
}

bool mgs_barrier_expired(struct fs_db *fsdb, time64_t timeout)
{
	time64_t expired = fsdb->fsdb_barrier_latest_create_time + timeout;

	return expired > ktime_get_real_seconds();
}

/**
 * Create the barrier for the given instance.
 *
 * We use two-phases barrier to guarantee that after the barrier setup:
 * 1) All the server side pending async modification RPCs have been flushed.
 * 2) Any subsequent modification will be blocked.
 * 3) All async transactions on the MDTs have been committed.
 *
 * For phase1, we do the following:
 *
 * Firstly, it sets barrier flag on the instance that will block subsequent
 * modifications from clients. (Note: server sponsored modification will be
 * allowed for flush pending modifications)
 *
 * Secondly, it will flush all pending modification via dt_sync(), such as
 * async OST-object destroy, async OST-object owner changes, and so on.
 *
 * If there are some on-handling clients sponsored modifications during the
 * barrier creating, then related modifications may cause pending requests
 * after the first dt_sync(), so call dt_sync() again after all on-handling
 * modifications done.
 *
 * With the phase1 barrier set, all pending cross-servers modification RPCs
 * have been flushed to remote servers, and any new modification will be
 * blocked. But it does not guarantees that all the updates have been
 * committed to storage on remote servers. So when all the instances have
 * done phase1 barrier successfully, the MGS will notify all instances to
 * do the phase2 barrier as following:
 *
 * Every barrier instance will call dt_sync() to make all async transactions
 * to be committed locally.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] mgs	pointer to the MGS device
 * \param[in] bc	pointer the barrier control structure
 *
 * \retval		0 for success
 * \retval		negative error number on failure
 */
static int mgs_barrier_freeze(const struct lu_env *env,
			      struct mgs_device *mgs,
			      struct barrier_ctl *bc)
{
	char *name = mgs_env_info(env)->mgi_fsname;
	struct fs_db *fsdb;
	int rc = 0;
	time64_t left;
	bool phase1 = true;
	bool dirty = false;
	ENTRY;

	snprintf(name, sizeof(mgs_env_info(env)->mgi_fsname) - 1, "%s-%s",
		 bc->bc_name, BARRIER_FILENAME);

	down_write(&mgs->mgs_barrier_rwsem);
	mutex_lock(&mgs->mgs_mutex);

	rc = mgs_find_or_make_fsdb_nolock(env, mgs, name, &fsdb);
	if (rc) {
		mutex_unlock(&mgs->mgs_mutex);
		up_write(&mgs->mgs_barrier_rwsem);
		RETURN(rc);
	}

	if (unlikely(fsdb->fsdb_mdt_count == 0)) {
		mgs_barrier_bitmap_setup(mgs, fsdb, bc->bc_name);

		/* fsdb was just created, ensure that fsdb_barrier_disabled is
		 * set correctly */
		if (fsdb->fsdb_mdt_count > 0) {
			struct obd_export *exp;
			struct obd_device *mgs_obd = mgs->mgs_obd;

			spin_lock(&mgs_obd->obd_dev_lock);
			list_for_each_entry(exp, &mgs_obd->obd_exports,
					    exp_obd_chain) {
				__u64 flags = exp_connect_flags(exp);
				if (!!(flags & OBD_CONNECT_MDS_MDS) &&
				    !(flags & OBD_CONNECT_BARRIER)) {
					fsdb->fsdb_barrier_disabled = 1;
					break;
				}
			}
			spin_unlock(&mgs_obd->obd_dev_lock);
		}
	}

	mutex_lock(&fsdb->fsdb_mutex);
	mutex_unlock(&mgs->mgs_mutex);

	switch (fsdb->fsdb_barrier_status) {
	case BS_THAWING:
	case BS_RESCAN:
		rc = -EBUSY;
		break;
	case BS_FREEZING_P1:
	case BS_FREEZING_P2:
		rc = -EINPROGRESS;
		break;
	case BS_FROZEN:
		if (mgs_barrier_expired(fsdb, fsdb->fsdb_barrier_timeout)) {
			rc = -EALREADY;
			break;
		}
		/* fallthrough */
	case BS_INIT:
	case BS_THAWED:
	case BS_EXPIRED:
	case BS_FAILED:
		if (fsdb->fsdb_barrier_disabled) {
			rc = -EOPNOTSUPP;
		} else if (unlikely(fsdb->fsdb_mdt_count == 0)) {
			rc = -ENODEV;
		} else {
			fsdb->fsdb_barrier_latest_create_time =
				ktime_get_real_seconds();
			fsdb->fsdb_barrier_status = BS_FREEZING_P1;
			if (bc->bc_timeout != 0)
				fsdb->fsdb_barrier_timeout = bc->bc_timeout;
			else
				fsdb->fsdb_barrier_timeout =
						BARRIER_TIMEOUT_DEFAULT;
			memset(fsdb->fsdb_barrier_map, 0, INDEX_MAP_SIZE);
		}
		break;
	default:
		LCONSOLE_WARN("%s: found unexpected barrier status %u\n",
			      bc->bc_name, fsdb->fsdb_barrier_status);
		rc = -EINVAL;
		LBUG();
	}

	if (rc)
		GOTO(out, rc);

	left = fsdb->fsdb_barrier_timeout;

again:
	mutex_unlock(&fsdb->fsdb_mutex);
	up_write(&mgs->mgs_barrier_rwsem);

	CFS_FAIL_TIMEOUT(OBD_FAIL_BARRIER_DELAY, cfs_fail_val);

	rc = mgs_barrier_glimpse_lock(env, mgs, fsdb, left,
				      phase1 ? BS_FREEZING_P1 : BS_FROZEN);
	down_write(&mgs->mgs_barrier_rwsem);
	mutex_lock(&fsdb->fsdb_mutex);

	dirty = true;
	left = fsdb->fsdb_barrier_latest_create_time +
	       fsdb->fsdb_barrier_timeout - ktime_get_real_seconds();
	if (left <= 0) {
		fsdb->fsdb_barrier_status = BS_EXPIRED;

		GOTO(out, rc = -ETIME);
	}

	LASSERTF(fsdb->fsdb_barrier_status ==
		 (phase1 ? BS_FREEZING_P1 : BS_FREEZING_P2),
		 "unexpected barrier status %u\n",
		 fsdb->fsdb_barrier_status);

	if (rc == -ETIMEDOUT) {
		fsdb->fsdb_barrier_status = BS_EXPIRED;
		rc = -ETIME;
	} else if (rc > 0) {
		fsdb->fsdb_barrier_status = rc;
		rc = -EREMOTE;
	} else if (rc < 0) {
		fsdb->fsdb_barrier_status = BS_FAILED;
	} else if (mgs_barrier_done(fsdb)) {
		if (phase1) {
			fsdb->fsdb_barrier_status = BS_FREEZING_P2;
			memset(fsdb->fsdb_barrier_map, 0,
			       INDEX_MAP_SIZE);
			phase1 = false;

			goto again;
		} else {
			fsdb->fsdb_barrier_status = BS_FROZEN;
		}
	} else {
		fsdb->fsdb_barrier_status = BS_FAILED;
		rc = -EREMOTE;
	}

	GOTO(out, rc);

out:
	mutex_unlock(&fsdb->fsdb_mutex);
	up_write(&mgs->mgs_barrier_rwsem);
	if (rc && dirty) {
		memset(fsdb->fsdb_barrier_map, 0, INDEX_MAP_SIZE);
		mgs_barrier_glimpse_lock(env, mgs, fsdb, 0, BS_THAWED);
	}

	mgs_put_fsdb(mgs, fsdb);

	return rc;
}

static int mgs_barrier_thaw(const struct lu_env *env,
			    struct mgs_device *mgs,
			    struct barrier_ctl *bc)
{
	char *name = mgs_env_info(env)->mgi_fsname;
	struct fs_db *fsdb;
	int rc = 0;
	ENTRY;

	snprintf(name, sizeof(mgs_env_info(env)->mgi_fsname) - 1, "%s-%s",
		 bc->bc_name, BARRIER_FILENAME);

	down_write(&mgs->mgs_barrier_rwsem);
	mutex_lock(&mgs->mgs_mutex);

	rc = mgs_find_or_make_fsdb_nolock(env, mgs, name, &fsdb);
	if (rc) {
		mutex_unlock(&mgs->mgs_mutex);
		up_write(&mgs->mgs_barrier_rwsem);
		RETURN(rc);
	}

	if (unlikely(fsdb->fsdb_mdt_count == 0)) {
		mgs_barrier_bitmap_setup(mgs, fsdb, bc->bc_name);

		/* fsdb was just created, ensure that fsdb_barrier_disabled is
		 * set correctly */
		if (fsdb->fsdb_mdt_count > 0) {
			struct obd_export *exp;
			struct obd_device *mgs_obd = mgs->mgs_obd;

			spin_lock(&mgs_obd->obd_dev_lock);
			list_for_each_entry(exp, &mgs_obd->obd_exports,
					    exp_obd_chain) {
				__u64 flags = exp_connect_flags(exp);
				if (!!(flags & OBD_CONNECT_MDS_MDS) &&
				    !(flags & OBD_CONNECT_BARRIER)) {
					fsdb->fsdb_barrier_disabled = 1;
					break;
				}
			}
			spin_unlock(&mgs_obd->obd_dev_lock);
		}
	}

	mutex_lock(&fsdb->fsdb_mutex);
	mutex_unlock(&mgs->mgs_mutex);

	switch (fsdb->fsdb_barrier_status) {
	case BS_FREEZING_P1:
	case BS_FREEZING_P2:
	case BS_RESCAN:
		rc = -EBUSY;
		break;
	case BS_INIT:
	case BS_THAWED:
		rc = -EALREADY;
		break;
	case BS_THAWING:
		rc = -EINPROGRESS;
		break;
	case BS_FROZEN:
	case BS_EXPIRED: /* The barrier on some MDT(s) may be expired,
			  * but may be not on others. Destory anyway. */
	case BS_FAILED:
		if (unlikely(fsdb->fsdb_mdt_count == 0)) {
			rc = -ENODEV;
		} else {
			fsdb->fsdb_barrier_status = BS_THAWING;
			memset(fsdb->fsdb_barrier_map, 0, INDEX_MAP_SIZE);
		}
		break;
	default:
		LCONSOLE_WARN("%s: found unexpected barrier status %u\n",
			      bc->bc_name, fsdb->fsdb_barrier_status);
		rc = -EINVAL;
		LBUG();
	}

	if (rc)
		GOTO(out, rc);

	mutex_unlock(&fsdb->fsdb_mutex);
	up_write(&mgs->mgs_barrier_rwsem);

	CFS_FAIL_TIMEOUT(OBD_FAIL_BARRIER_DELAY, cfs_fail_val);

	rc = mgs_barrier_glimpse_lock(env, mgs, fsdb, 0, BS_THAWED);
	down_write(&mgs->mgs_barrier_rwsem);
	mutex_lock(&fsdb->fsdb_mutex);

	LASSERTF(fsdb->fsdb_barrier_status == BS_THAWING,
		 "unexpected barrier status %u\n",
		 fsdb->fsdb_barrier_status);

	if (rc > 0) {
		fsdb->fsdb_barrier_status = rc;
		rc = -EREMOTE;
	} else if (rc < 0) {
		fsdb->fsdb_barrier_status = BS_FAILED;
	} else if (mgs_barrier_done(fsdb)) {
		fsdb->fsdb_barrier_status = BS_THAWED;
	} else {
		fsdb->fsdb_barrier_status = BS_FAILED;
		rc = -EREMOTE;
	}

	GOTO(out, rc);

out:
	mutex_unlock(&fsdb->fsdb_mutex);
	up_write(&mgs->mgs_barrier_rwsem);
	mgs_put_fsdb(mgs, fsdb);

	return rc;
}

static int mgs_barrier_stat(const struct lu_env *env,
			    struct mgs_device *mgs,
			    struct barrier_ctl *bc)
{
	char *name = mgs_env_info(env)->mgi_fsname;
	struct fs_db *fsdb;
	ENTRY;

	snprintf(name, sizeof(mgs_env_info(env)->mgi_fsname) - 1, "%s-%s",
		 bc->bc_name, BARRIER_FILENAME);

	mutex_lock(&mgs->mgs_mutex);

	fsdb = mgs_find_fsdb(mgs, name);
	if (fsdb) {
		mutex_lock(&fsdb->fsdb_mutex);
		mutex_unlock(&mgs->mgs_mutex);

		bc->bc_status = fsdb->fsdb_barrier_status;
		if (bc->bc_status == BS_FREEZING_P1 ||
		    bc->bc_status == BS_FREEZING_P2 ||
		    bc->bc_status == BS_FROZEN) {
			if (mgs_barrier_expired(fsdb, fsdb->fsdb_barrier_timeout))
				bc->bc_timeout =
					fsdb->fsdb_barrier_latest_create_time +
					fsdb->fsdb_barrier_timeout -
					ktime_get_real_seconds();
			else
				bc->bc_status = fsdb->fsdb_barrier_status =
					BS_EXPIRED;
		}

		mutex_unlock(&fsdb->fsdb_mutex);
		mgs_put_fsdb(mgs, fsdb);
	} else {
		mutex_unlock(&mgs->mgs_mutex);

		bc->bc_status = BS_INIT;
	}

	RETURN(0);
}

static int mgs_barrier_rescan(const struct lu_env *env,
			      struct mgs_device *mgs,
			      struct barrier_ctl *bc)
{
	char *name = mgs_env_info(env)->mgi_fsname;
	struct fs_db *b_fsdb;
	struct fs_db *c_fsdb;
	int rc = 0;
	ENTRY;

	down_write(&mgs->mgs_barrier_rwsem);
	mutex_lock(&mgs->mgs_mutex);

	c_fsdb = mgs_find_fsdb(mgs, bc->bc_name);
	if (!c_fsdb || unlikely(c_fsdb->fsdb_mdt_count == 0)) {
		mutex_unlock(&mgs->mgs_mutex);
		up_write(&mgs->mgs_barrier_rwsem);

		RETURN(-ENODEV);
	}

	snprintf(name, sizeof(mgs_env_info(env)->mgi_fsname) - 1, "%s-%s",
		 bc->bc_name, BARRIER_FILENAME);
	rc = mgs_find_or_make_fsdb_nolock(env, mgs, name, &b_fsdb);
	if (rc) {
		mutex_unlock(&mgs->mgs_mutex);
		up_write(&mgs->mgs_barrier_rwsem);
		mgs_put_fsdb(mgs, c_fsdb);
		RETURN(rc);
	}

	if (unlikely(b_fsdb->fsdb_mdt_count == 0 &&
		     c_fsdb->fsdb_mdt_count > 0)) {
		/* fsdb was just created, ensure that fsdb_barrier_disabled is
		 * set correctly */
		struct obd_export *exp;
		struct obd_device *mgs_obd = mgs->mgs_obd;

		spin_lock(&mgs_obd->obd_dev_lock);
		list_for_each_entry(exp, &mgs_obd->obd_exports,
				    exp_obd_chain) {
			__u64 flags = exp_connect_flags(exp);
			if (!!(flags & OBD_CONNECT_MDS_MDS) &&
			    !(flags & OBD_CONNECT_BARRIER)) {
				b_fsdb->fsdb_barrier_disabled = 1;
				break;
			}
		}
		spin_unlock(&mgs_obd->obd_dev_lock);
	}

	mutex_lock(&b_fsdb->fsdb_mutex);
	mutex_lock(&c_fsdb->fsdb_mutex);
	mutex_unlock(&mgs->mgs_mutex);

	switch (b_fsdb->fsdb_barrier_status) {
	case BS_RESCAN:
		rc = -EINPROGRESS;
		break;
	case BS_THAWING:
	case BS_FREEZING_P1:
	case BS_FREEZING_P2:
		rc = -EBUSY;
		break;
	case BS_FROZEN:
		if (mgs_barrier_expired(b_fsdb, b_fsdb->fsdb_barrier_timeout)) {
			rc = -EBUSY;
			break;
		}
		/* fallthrough */
	case BS_INIT:
	case BS_THAWED:
	case BS_EXPIRED:
	case BS_FAILED:
		b_fsdb->fsdb_barrier_latest_create_time = ktime_get_real_seconds();
		b_fsdb->fsdb_barrier_status = BS_RESCAN;
		memcpy(b_fsdb->fsdb_mdt_index_map, c_fsdb->fsdb_mdt_index_map,
		       INDEX_MAP_SIZE);
		memset(b_fsdb->fsdb_barrier_map, 0, INDEX_MAP_SIZE);
		b_fsdb->fsdb_mdt_count = c_fsdb->fsdb_mdt_count;
		break;
	default:
		LCONSOLE_WARN("%s: found unexpected barrier status %u\n",
			      bc->bc_name, b_fsdb->fsdb_barrier_status);
		rc = -EINVAL;
		LBUG();
	}

	mutex_unlock(&c_fsdb->fsdb_mutex);
	mgs_put_fsdb(mgs, c_fsdb);

	if (rc)
		GOTO(out, rc);

again:
	mutex_unlock(&b_fsdb->fsdb_mutex);
	up_write(&mgs->mgs_barrier_rwsem);
	rc = mgs_barrier_glimpse_lock(env, mgs, b_fsdb, 0, BS_INIT);
	down_write(&mgs->mgs_barrier_rwsem);
	mutex_lock(&b_fsdb->fsdb_mutex);

	LASSERTF(b_fsdb->fsdb_barrier_status == BS_RESCAN,
		 "unexpected barrier status %u\n",
		 b_fsdb->fsdb_barrier_status);

	if (rc > 0) {
		b_fsdb->fsdb_barrier_status = rc;
		rc = -EREMOTE;
	} else if (rc == -ETIMEDOUT &&
		   mgs_barrier_expired(b_fsdb, bc->bc_timeout)) {
		memset(b_fsdb->fsdb_barrier_map, 0, INDEX_MAP_SIZE);

		goto again;
	} else if (rc < 0 && rc != -ETIMEDOUT && rc != -ENODEV) {
		b_fsdb->fsdb_barrier_status = BS_FAILED;
	} else {
		int i;

		b_fsdb->fsdb_mdt_count = 0;
		bc->bc_total = 0;
		bc->bc_absence = 0;
		rc = 0;
		for (i = 0; i < INDEX_MAP_SIZE * 8; i++) {
			if (test_bit(i, b_fsdb->fsdb_barrier_map)) {
				b_fsdb->fsdb_mdt_count++;
			} else if (test_bit(i, b_fsdb->fsdb_mdt_index_map)) {
				b_fsdb->fsdb_mdt_count++;
				bc->bc_absence++;
			}
		}

		bc->bc_total = b_fsdb->fsdb_mdt_count;
		memcpy(b_fsdb->fsdb_mdt_index_map,
		       b_fsdb->fsdb_barrier_map, INDEX_MAP_SIZE);
		b_fsdb->fsdb_barrier_status = BS_INIT;
	}

	GOTO(out, rc);

out:
	mutex_unlock(&b_fsdb->fsdb_mutex);
	up_write(&mgs->mgs_barrier_rwsem);
	mgs_put_fsdb(mgs, b_fsdb);

	return rc;
}

int mgs_iocontrol_barrier(const struct lu_env *env,
			  struct mgs_device *mgs,
			  struct obd_ioctl_data *data)
{
	struct barrier_ctl *bc = (struct barrier_ctl *)(data->ioc_inlbuf1);
	int rc;
	ENTRY;

	if (unlikely(bc->bc_version != BARRIER_VERSION_V1))
		RETURN(-EOPNOTSUPP);

	if (unlikely(bc->bc_name[0] == '\0' ||
		     strnlen(bc->bc_name, sizeof(bc->bc_name)) > 8))
		RETURN(-EINVAL);

	/* NOT allow barrier operations during recovery. */
	if (unlikely(mgs->mgs_obd->obd_recovering))
		RETURN(-EBUSY);

	switch (bc->bc_cmd) {
	case BC_FREEZE:
		rc = mgs_barrier_freeze(env, mgs, bc);
		break;
	case BC_THAW:
		rc = mgs_barrier_thaw(env, mgs, bc);
		break;
	case BC_STAT:
		rc = mgs_barrier_stat(env, mgs, bc);
		break;
	case BC_RESCAN:
		rc = mgs_barrier_rescan(env, mgs, bc);
		break;
	default:
		rc = -EINVAL;
		break;
	}

	RETURN(rc);
}
