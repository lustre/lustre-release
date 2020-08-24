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
 * (C) Copyright 2012 Commissariat a l'energie atomique et aux energies
 *     alternatives
 *
 * Copyright (c) 2013, 2017, Intel Corporation.
 */
/*
 * lustre/mdt/mdt_hsm_cdt_client.c
 *
 * Lustre HSM Coordinator
 *
 * Author: Jacques-Charles Lafoucriere <jacques-charles.lafoucriere@cea.fr>
 * Author: Aurelien Degremont <aurelien.degremont@cea.fr>
 */

#define DEBUG_SUBSYSTEM S_MDS

#include <obd_support.h>
#include <lustre_export.h>
#include <obd.h>
#include <lprocfs_status.h>
#include <lustre_log.h>
#include "mdt_internal.h"

/**
 * llog_cat_process() callback, used to find record
 * compatibles with a new hsm_action_list
 * \param env [IN] environment
 * \param llh [IN] llog handle
 * \param hdr [IN] llog record
 * \param data [IN] cb data = hal
 * \retval 0 success
 * \retval -ve failure
 */
static int hsm_find_compatible_cb(const struct lu_env *env,
				  struct llog_handle *llh,
				  struct llog_rec_hdr *hdr, void *data)
{
	struct llog_agent_req_rec *larr = (struct llog_agent_req_rec *)hdr;
	struct hsm_action_list *hal = data;
	struct hsm_action_item *hai;
	int i;
	ENTRY;

	/* a compatible request must be WAITING or STARTED
	 * and not a cancel */
	if ((larr->arr_status != ARS_WAITING &&
	     larr->arr_status != ARS_STARTED) ||
	    larr->arr_hai.hai_action == HSMA_CANCEL)
		RETURN(0);

	hai = hai_first(hal);
	for (i = 0; i < hal->hal_count; i++, hai = hai_next(hai)) {
		/* if request is a CANCEL:
		 * if cookie set in the request, there is no need to find a
		 * compatible one, the cookie in the request is directly used.
		 * if cookie is not set, we use the FID to find the request
		 * to cancel (the "compatible" one)
		 * if the caller sets the cookie, we assume he also sets the
		 * arr_archive_id
		 */
		if (hai->hai_action == HSMA_CANCEL && hai->hai_cookie != 0)
			continue;

		if (!lu_fid_eq(&hai->hai_fid, &larr->arr_hai.hai_fid))
			continue;

		/* in V1 we do not manage partial transfer
		 * so extent is always whole file
		 */
		hai->hai_cookie = larr->arr_hai.hai_cookie;
		/* we read the archive number from the request we cancel */
		if (hai->hai_action == HSMA_CANCEL && hal->hal_archive_id == 0)
			hal->hal_archive_id = larr->arr_archive_id;
	}
	RETURN(0);
}

/**
 * find compatible requests already recorded
 * \param env [IN] environment
 * \param mdt [IN] MDT device
 * \param hal [IN/OUT] new request
 *    cookie set to compatible found or to 0 if not found
 *    for cancel request, see callback hsm_find_compatible_cb()
 * \retval 0 success
 * \retval -ve failure
 */
static int hsm_find_compatible(const struct lu_env *env, struct mdt_device *mdt,
			       struct hsm_action_list *hal)
{
	struct hsm_action_item *hai;
	int rc = 0, i;
	bool check = false;
	ENTRY;

	hai = hai_first(hal);
	for (i = 0; i < hal->hal_count; i++, hai = hai_next(hai)) {
		/* We only support ARCHIVE, RESTORE, REMOVE and CANCEL here. */
		if (hai->hai_action == HSMA_NONE)
			RETURN(-EINVAL);

		/* In a cancel request hai_cookie may be set by caller to show
		 * the request to be canceled. If there is at least one cancel
		 * request that does not have a cookie set we need to search by
		 * FID; we can skip checking in all other cases
		 */
		if (hai->hai_action == HSMA_CANCEL && hai->hai_cookie == 0) {
			check = true;
			break;
		}
	}

	if (check)
		rc = cdt_llog_process(env, mdt, hsm_find_compatible_cb, hal, 0,
					      0, READ);

	RETURN(rc);
}

/**
 * check if an action is really needed
 * \param hai [IN] request description
 * \param hal_an [IN] request archive number (not used)
 * \param rq_flags [IN] request flags
 * \param hsm [IN] file HSM metadata
 * \retval boolean
 */
static bool hsm_action_is_needed(struct hsm_action_item *hai, int hal_an,
				 __u64 rq_flags, struct md_hsm *hsm)
{
	bool	 is_needed = false;
	int	 hsm_flags;
	ENTRY;

	if (rq_flags & HSM_FORCE_ACTION)
		RETURN(true);

	hsm_flags = hsm->mh_flags;
	switch (hai->hai_action) {
	case HSMA_ARCHIVE:
		if (hsm_flags & HS_DIRTY || !(hsm_flags & HS_ARCHIVED))
			is_needed = true;
		break;
	case HSMA_RESTORE:
		/* if file is dirty we must return an error, this function
		 * cannot, so we ask for an action and
		 * mdt_hsm_is_action_compat() will return an error
		 */
		if (hsm_flags & (HS_RELEASED | HS_DIRTY))
			is_needed = true;
		break;
	case HSMA_REMOVE:
		if (hsm_flags & (HS_ARCHIVED | HS_EXISTS))
			is_needed = true;
		break;
	case HSMA_CANCEL:
		is_needed = true;
		break;
	}
	CDEBUG(D_HSM, "fid="DFID" action=%s rq_flags=%#llx"
		      " extent=%#llx-%#llx hsm_flags=%X %s\n",
		      PFID(&hai->hai_fid),
		      hsm_copytool_action2name(hai->hai_action), rq_flags,
		      hai->hai_extent.offset, hai->hai_extent.length,
		      hsm->mh_flags,
		      (is_needed ? "action needed" : "no action needed"));

	RETURN(is_needed);
}

/**
 * test sanity of an hal
 * FID must be valid
 * action must be known
 * \param hal [IN]
 * \retval boolean
 */
static bool hal_is_sane(struct hsm_action_list *hal)
{
	int			 i;
	struct hsm_action_item	*hai;
	ENTRY;

	if (hal->hal_count == 0)
		RETURN(false);

	hai = hai_first(hal);
	for (i = 0; i < hal->hal_count; i++, hai = hai_next(hai)) {
		if (!fid_is_sane(&hai->hai_fid))
			RETURN(false);
		switch (hai->hai_action) {
		case HSMA_NONE:
		case HSMA_ARCHIVE:
		case HSMA_RESTORE:
		case HSMA_REMOVE:
		case HSMA_CANCEL:
			break;
		default:
			RETURN(false);
		}
	}
	RETURN(true);
}

static int
hsm_action_permission(struct mdt_thread_info *mti,
		      struct mdt_object *obj,
		      enum hsm_copytool_action hsma)
{
	struct coordinator *cdt = &mti->mti_mdt->mdt_coordinator;
	struct lu_ucred *uc = mdt_ucred(mti);
	struct md_attr *ma = &mti->mti_attr;
	const __u64 *mask;
	int rc;
	ENTRY;

	if (hsma != HSMA_RESTORE && mdt_rdonly(mti->mti_exp))
		RETURN(-EROFS);

	if (md_capable(uc, CAP_SYS_ADMIN))
		RETURN(0);

	ma->ma_need = MA_INODE;
	rc = mdt_attr_get_complex(mti, obj, ma);
	if (rc < 0)
		RETURN(rc);

	if (uc->uc_fsuid == ma->ma_attr.la_uid)
		mask = &cdt->cdt_user_request_mask;
	else if (lustre_in_group_p(uc, ma->ma_attr.la_gid))
		mask = &cdt->cdt_group_request_mask;
	else
		mask = &cdt->cdt_other_request_mask;

	if (!(0 <= hsma && hsma < 8 * sizeof(*mask)))
		RETURN(-EINVAL);

	RETURN(*mask & (1UL << hsma) ? 0 : -EPERM);
}

/* Process a single HAL. hsm_find_compatible has already been called
 * on it. */
static int mdt_hsm_register_hal(struct mdt_thread_info *mti,
				struct mdt_device *mdt,
				struct coordinator *cdt,
				struct hsm_action_list *hal)
{
	struct hsm_action_item	*hai;
	struct mdt_object	*obj = NULL;
	int			 rc, i;
	struct md_hsm		 mh;
	bool			 is_restore = false;

	hai = hai_first(hal);
	for (i = 0; i < hal->hal_count; i++, hai = hai_next(hai)) {
		int archive_id;
		__u64 flags;

		/* default archive number is the one explicitly specified */
		archive_id = hal->hal_archive_id;
		flags = hal->hal_flags;

		/* by default, data FID is same as Lustre FID */
		/* the volatile data FID will be created by copy tool and
		 * send from the agent through the progress call */
		hai->hai_dfid = hai->hai_fid;

		/* done here to manage first and redundant requests cases */
		if (hai->hai_action == HSMA_RESTORE)
			is_restore = true;

		/* test result of hsm_find_compatible()
		 * if request redundant or cancel of nothing
		 * do not record
		 */
		/* redundant case */
		if (hai->hai_action != HSMA_CANCEL && hai->hai_cookie != 0)
			continue;
		/* cancel nothing case */
		if (hai->hai_action == HSMA_CANCEL && hai->hai_cookie == 0)
			continue;

		/* new request or cancel request
		 * we search for HSM status flags to check for compatibility
		 * if restore, we take the layout lock
		 */

		/* Get HSM attributes and check permissions. */
		obj = mdt_hsm_get_md_hsm(mti, &hai->hai_fid, &mh);
		if (IS_ERR(obj)) {
			/* In case of REMOVE and CANCEL a Lustre file
			 * is not mandatory, but restrict this
			 * exception to admins. */
			if (md_capable(mdt_ucred(mti), CAP_SYS_ADMIN) &&
			    (hai->hai_action == HSMA_REMOVE ||
			     hai->hai_action == HSMA_CANCEL))
				goto record;
			else
				GOTO(out, rc = PTR_ERR(obj));
		}

		rc = hsm_action_permission(mti, obj, hai->hai_action);
		mdt_object_put(mti->mti_env, obj);

		if (rc < 0)
			GOTO(out, rc);

		/* if action is cancel, also no need to check */
		if (hai->hai_action == HSMA_CANCEL)
			goto record;

		/* Check if an action is needed, compare request
		 * and HSM flags status */
		if (!hsm_action_is_needed(hai, archive_id, flags, &mh))
			continue;

		/* Check if file request is compatible with HSM flags status
		 * and stop at first incompatible
		 */
		if (!mdt_hsm_is_action_compat(hai, archive_id, flags, &mh))
			GOTO(out, rc = -EPERM);

		/* for cancel archive number is taken from canceled request
		 * for other request, we take from lma if not specified,
		 * or we use the default if none found in lma
		 * this works also for archive because the default value is 0
		 * /!\ there is a side effect: in case of restore on multiple
		 * files which are in different backend, the initial
		 * request will be split in multiple requests because we cannot
		 * warranty an agent can serve any combinaison of archive
		 * backend
		 */
		if (hai->hai_action != HSMA_CANCEL && archive_id == 0) {
			if (mh.mh_arch_id != 0)
				archive_id = mh.mh_arch_id;
			else
				archive_id = cdt->cdt_default_archive_id;
		}

		/* if restore, take an exclusive lock on layout */
		if (hai->hai_action == HSMA_RESTORE) {
			/* in V1 only whole file is supported. */
			if (hai->hai_extent.offset != 0)
				GOTO(out, rc = -EPROTO);

			rc = cdt_restore_handle_add(mti, cdt, &hai->hai_fid,
						    &hai->hai_extent);
			if (rc < 0)
				GOTO(out, rc);
		}
record:
		/*
		 * Wait here to catch the 2nd RESTORE request to the same FID.
		 * Normally layout lock protects against adding such request.
		 * But when cdt is stopping it cancel all locks via
		 * ldlm_resource_clean and protections may not work.
		 * See LU-9266 and sanity-hsm_407 for details.
		 */
		OBD_FAIL_TIMEOUT(OBD_FAIL_MDS_HSM_CDT_DELAY, cfs_fail_val);
		/* record request */
		rc = mdt_agent_record_add(mti->mti_env, mdt, archive_id, flags,
					  hai);
		if (rc)
			GOTO(out, rc);
	}
	if (is_restore &&
	    (cdt->cdt_policy & CDT_NONBLOCKING_RESTORE))
		rc = -ENODATA;
	else
		rc = 0;

	GOTO(out, rc);

out:
	return rc;
}

/*
 * Coordinator external API
 */

/**
 * register a list of requests
 * \param mti [IN]
 * \param hal [IN] list of requests
 * \retval 0 success
 * \retval -ve failure
 * in case of restore, caller must hold layout lock
 */
int mdt_hsm_add_actions(struct mdt_thread_info *mti,
			struct hsm_action_list *hal)
{
	struct mdt_device	*mdt = mti->mti_mdt;
	struct coordinator	*cdt = &mdt->mdt_coordinator;
	int			 rc;
	ENTRY;

	/* no coordinator started, so we cannot serve requests */
	if (cdt->cdt_state == CDT_STOPPED || cdt->cdt_state == CDT_INIT)
		RETURN(-EAGAIN);

	if (!hal_is_sane(hal))
		RETURN(-EINVAL);

	/* search for compatible request, if found hai_cookie is set
	 * to the request cookie
	 * it is also used to set the cookie for cancel request by FID
	 */
	rc = hsm_find_compatible(mti->mti_env, mdt, hal);
	if (rc)
		GOTO(out, rc);

	rc = mdt_hsm_register_hal(mti, mdt, cdt, hal);

	GOTO(out, rc);
out:
	/* if work has been added, signal the coordinator */
	if (rc == 0 || rc == -ENODATA)
		mdt_hsm_cdt_event(cdt);

	return rc;
}

/**
 * check if a restore is running on a FID
 * this is redundant with mdt_hsm_coordinator_get_running()
 * but as it can be called frequently when getting attr
 * we make an optimized/simpler version only for a FID
 * \param mti [IN]
 * \param fid [IN] file FID
 * \retval boolean
 */
bool mdt_hsm_restore_is_running(struct mdt_thread_info *mti,
				const struct lu_fid *fid)
{
	struct coordinator *cdt = &mti->mti_mdt->mdt_coordinator;
	bool is_running;
	ENTRY;

	mutex_lock(&cdt->cdt_restore_lock);
	is_running = (cdt_restore_handle_find(cdt, fid) != NULL);
	mutex_unlock(&cdt->cdt_restore_lock);

	RETURN(is_running);
}

struct hsm_get_action_data {
	const struct lu_fid *hgad_fid;
	struct hsm_action_item hgad_hai;
	enum agent_req_status hgad_status;
};

static int hsm_get_action_cb(const struct lu_env *env,
			     struct llog_handle *llh,
			     struct llog_rec_hdr *hdr, void *data)
{
	struct llog_agent_req_rec *larr = (struct llog_agent_req_rec *)hdr;
	struct hsm_get_action_data *hgad = data;

	/* A compatible request must be WAITING or STARTED and not a
	 * cancel. */
	if ((larr->arr_status != ARS_WAITING &&
	     larr->arr_status != ARS_STARTED) ||
	    larr->arr_hai.hai_action == HSMA_CANCEL ||
	    !lu_fid_eq(&larr->arr_hai.hai_fid, hgad->hgad_fid))
		RETURN(0);

	hgad->hgad_hai = larr->arr_hai;
	hgad->hgad_status = larr->arr_status;

	RETURN(LLOG_PROC_BREAK);
}

/**
 * get registered action on a FID
 * \param mti [IN]
 * \param fid [IN]
 * \param action [OUT]
 * \param status [OUT]
 * \param extent [OUT]
 * \retval 0 success
 * \retval -ve failure
 */
int mdt_hsm_get_action(struct mdt_thread_info *mti,
		       const struct lu_fid *fid,
		       enum hsm_copytool_action *action,
		       enum agent_req_status *status,
		       struct hsm_extent *extent)
{
	const struct lu_env *env = mti->mti_env;
	struct mdt_device *mdt = mti->mti_mdt;
	struct coordinator *cdt = &mdt->mdt_coordinator;
	struct hsm_get_action_data hgad = {
		.hgad_fid = fid,
		.hgad_hai.hai_action = HSMA_NONE,
	};
	struct cdt_agent_req *car;
	int rc;
	ENTRY;

	/* 1st we search in recorded requests */
	rc = cdt_llog_process(env, mdt, hsm_get_action_cb, &hgad, 0, 0, READ);
	if (rc < 0)
		RETURN(rc);

	*action = hgad.hgad_hai.hai_action;
	*extent = hgad.hgad_hai.hai_extent;
	*status = hgad.hgad_status;

	if (*action == HSMA_NONE || *status != ARS_STARTED)
		RETURN(0);

	car = mdt_cdt_find_request(cdt, hgad.hgad_hai.hai_cookie);
	if (car) {
		/* This is just to give the volume of data moved.
		 * It means 'car_progress' data have been moved from the
		 * original request but we do not know which one.
		 */
		extent->length = car->car_progress.crp_total;
		mdt_cdt_put_request(car);
	}

	RETURN(0);
}
