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
 * Copyright (c) 2011, 2012 Commissariat a l'energie atomique et aux energies
 *                          alternatives
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2015, Intel Corporation.
 */
/*
 * lustre/mdt/mdt_hsm.c
 *
 * Lustre Metadata Target (mdt) request handler
 *
 * Author: Aurelien Degremont <aurelien.degremont@cea.fr>
 * Author: JC Lafoucriere <jacques-charles.lafoucriere@cea.fr>
 */

#define DEBUG_SUBSYSTEM S_MDS

#include <lustre_errno.h>
#include "mdt_internal.h"

/* Max allocation to satisfy single HSM RPC. */
#define MDT_HSM_ALLOC_MAX (1 << 20)

#define MDT_HSM_ALLOC(ptr, size)			\
	do {						\
		if ((size) <= MDT_HSM_ALLOC_MAX)	\
			OBD_ALLOC_LARGE((ptr), (size));	\
		else					\
			(ptr) = NULL;			\
	} while (0)

#define MDT_HSM_FREE(ptr, size) OBD_FREE_LARGE((ptr), (size))

/**
 * Update on-disk HSM attributes.
 */
int mdt_hsm_attr_set(struct mdt_thread_info *info, struct mdt_object *obj,
		     const struct md_hsm *mh)
{
	struct md_object *next = mdt_object_child(obj);
	struct lu_buf *buf = &info->mti_buf;
	struct hsm_attrs *attrs;
	int rc;
	ENTRY;

	attrs = (struct hsm_attrs *)info->mti_xattr_buf;
	BUILD_BUG_ON(sizeof(info->mti_xattr_buf) < sizeof(*attrs));

	/* pack HSM attributes */
	lustre_hsm2buf(info->mti_xattr_buf, mh);

	/* update HSM attributes */
	buf->lb_buf = attrs;
	buf->lb_len = sizeof(*attrs);
	rc = mo_xattr_set(info->mti_env, next, buf, XATTR_NAME_HSM, 0);

	RETURN(rc);
}

static inline bool mdt_hsm_is_admin(struct mdt_thread_info *info)
{
	bool is_admin;
	int rc;

	if (info->mti_body == NULL)
		return false;

	rc = mdt_init_ucred(info, (struct mdt_body *)info->mti_body);
	if (rc < 0)
		return false;

	is_admin = md_capable(mdt_ucred(info), CAP_SYS_ADMIN);

	mdt_exit_ucred(info);

	return is_admin;
}

/**
 * Extract information coming from a copytool and asks coordinator to update
 * a request status depending on the update content.
 *
 * Copytools could use this to report failure in their process.
 *
 * This is HSM_PROGRESS RPC handler.
 */
int mdt_hsm_progress(struct tgt_session_info *tsi)
{
	struct mdt_thread_info		*info;
	struct hsm_progress_kernel	*hpk;
	int				 rc;
	ENTRY;

	if (tsi->tsi_mdt_body == NULL)
		RETURN(-EPROTO);

	hpk = req_capsule_client_get(tsi->tsi_pill, &RMF_MDS_HSM_PROGRESS);
	if (hpk == NULL)
		RETURN(err_serious(-EPROTO));

	hpk->hpk_errval = lustre_errno_ntoh(hpk->hpk_errval);

	CDEBUG(D_HSM, "Progress on "DFID": len=%llu : rc = %d\n",
	       PFID(&hpk->hpk_fid), hpk->hpk_extent.length, hpk->hpk_errval);

	if (hpk->hpk_errval)
		CDEBUG(D_HSM, "Copytool progress on "DFID" failed : rc = %d; %s.\n",
		       PFID(&hpk->hpk_fid), hpk->hpk_errval,
		       hpk->hpk_flags & HP_FLAG_RETRY ? "will retry" : "fatal");

	if (hpk->hpk_flags & HP_FLAG_COMPLETED)
		CDEBUG(D_HSM, "Finished "DFID" : rc = %d; cancel cookie=%#llx\n",
		       PFID(&hpk->hpk_fid), hpk->hpk_errval, hpk->hpk_cookie);

	info = tsi2mdt_info(tsi);
	if (!mdt_hsm_is_admin(info))
		GOTO(out, rc = -EPERM);

	rc = mdt_hsm_update_request_state(info, hpk);
out:
	mdt_thread_info_fini(info);
	RETURN(rc);
}

int mdt_hsm_ct_register(struct tgt_session_info *tsi)
{
	struct mdt_thread_info *info = tsi2mdt_info(tsi);
	struct ptlrpc_request *req = mdt_info_req(info);
	struct obd_export *exp = req->rq_export;
	size_t archives_size;
	__u32 *archives;
	int archive_count;
	int rc;
	ENTRY;

	if (!mdt_hsm_is_admin(info))
		GOTO(out, rc = -EPERM);

	archives = req_capsule_client_get(tsi->tsi_pill, &RMF_MDS_HSM_ARCHIVE);
	if (archives == NULL)
		GOTO(out, rc = err_serious(-EPROTO));

	archives_size = req_capsule_get_size(tsi->tsi_pill,
					     &RMF_MDS_HSM_ARCHIVE, RCL_CLIENT);

	/* compatibility check for the old clients */
	if (!exp_connect_archive_id_array(exp)) {
		if (archives_size != sizeof(*archives))
			GOTO(out, rc = err_serious(-EPROTO));

		/* XXX: directly include this function here? */
		rc = mdt_hsm_agent_register_mask(info,
						 &tsi->tsi_exp->exp_client_uuid,
						 *archives);
		GOTO(out, rc);
	}

	if (archives_size % sizeof(*archives) != 0)
		GOTO(out, rc = err_serious(-EPROTO));

	archive_count = archives_size / sizeof(*archives);
	if (archive_count == 1 && *archives == 0) {
		archive_count = 0;
		archives = NULL;
	}

	rc = mdt_hsm_agent_register(info, &tsi->tsi_exp->exp_client_uuid,
				    archive_count, archives);

out:
	mdt_thread_info_fini(info);
	RETURN(rc);
}

int mdt_hsm_ct_unregister(struct tgt_session_info *tsi)
{
	struct mdt_thread_info	*info;
	int			 rc;
	ENTRY;

	if (tsi->tsi_mdt_body == NULL)
		RETURN(-EPROTO);

	info = tsi2mdt_info(tsi);
	if (!mdt_hsm_is_admin(info))
		GOTO(out, rc = -EPERM);

	/* XXX: directly include this function here? */
	rc = mdt_hsm_agent_unregister(info, &tsi->tsi_exp->exp_client_uuid);
out:
	mdt_thread_info_fini(info);
	RETURN(rc);
}

/**
 * Retrieve the current HSM flags, archive id and undergoing HSM requests for
 * the fid provided in RPC body.
 *
 * Current requests are read from coordinator states.
 *
 * This is MDS_HSM_STATE_GET RPC handler.
 */
int mdt_hsm_state_get(struct tgt_session_info *tsi)
{
	struct mdt_thread_info	*info = tsi2mdt_info(tsi);
	struct mdt_object	*obj = info->mti_object;
	struct md_attr		*ma  = &info->mti_attr;
	struct hsm_user_state	*hus;
	struct mdt_lock_handle	*lh;
	int			 rc;
	ENTRY;

	if (info->mti_body == NULL || obj == NULL)
		GOTO(out, rc = -EPROTO);

	/* Only valid if client is remote */
	rc = mdt_init_ucred(info, (struct mdt_body *)info->mti_body);
	if (rc < 0)
		GOTO(out, rc = err_serious(rc));

	lh = &info->mti_lh[MDT_LH_CHILD];
	mdt_lock_reg_init(lh, LCK_PR);
	rc = mdt_object_lock(info, obj, lh, MDS_INODELOCK_LOOKUP);
	if (rc < 0)
		GOTO(out_ucred, rc);

	ma->ma_valid = 0;
	ma->ma_need = MA_HSM;
	rc = mdt_attr_get_complex(info, obj, ma);
	if (rc)
		GOTO(out_unlock, rc);

	hus = req_capsule_server_get(tsi->tsi_pill, &RMF_HSM_USER_STATE);
	if (hus == NULL)
		GOTO(out_unlock, rc = -EPROTO);

	/* Current HSM flags */
	hus->hus_states = ma->ma_hsm.mh_flags;
	hus->hus_archive_id = ma->ma_hsm.mh_arch_id;

	EXIT;
out_unlock:
	mdt_object_unlock(info, obj, lh, 1);
out_ucred:
	mdt_exit_ucred(info);
out:
	mdt_thread_info_fini(info);
	return rc;
}

/**
 * Change HSM state and archive number of a file.
 *
 * Archive number is changed iif the value is not 0.
 * The new flagset that will be computed should result in a coherent state.
 * This function checks that flags are compatible.
 *
 * This is MDS_HSM_STATE_SET RPC handler.
 */
int mdt_hsm_state_set(struct tgt_session_info *tsi)
{
	struct mdt_thread_info	*info = tsi2mdt_info(tsi);
	struct mdt_object	*obj = info->mti_object;
	struct md_attr          *ma = &info->mti_attr;
	struct hsm_state_set	*hss;
	struct mdt_lock_handle	*lh;
	int			 rc;
	__u64			 flags;
	ENTRY;

	hss = req_capsule_client_get(info->mti_pill, &RMF_HSM_STATE_SET);

	if (info->mti_body == NULL || obj == NULL || hss == NULL)
		GOTO(out, rc = -EPROTO);

	/* Only valid if client is remote */
	rc = mdt_init_ucred(info, (struct mdt_body *)info->mti_body);
	if (rc < 0)
		GOTO(out, rc = err_serious(rc));

	lh = &info->mti_lh[MDT_LH_CHILD];
	mdt_lock_reg_init(lh, LCK_PW);
	rc = mdt_object_lock(info, obj, lh, MDS_INODELOCK_LOOKUP |
			     MDS_INODELOCK_XATTR);
	if (rc < 0)
		GOTO(out_ucred, rc);

	/* Detect out-of range masks */
	if ((hss->hss_setmask | hss->hss_clearmask) & ~HSM_FLAGS_MASK) {
		CDEBUG(D_HSM, "Incompatible masks provided (set %#llx"
		       ", clear %#llx) vs supported set (%#x).\n",
		       hss->hss_setmask, hss->hss_clearmask, HSM_FLAGS_MASK);
		GOTO(out_unlock, rc = -EINVAL);
	}

	/* Non-root users are forbidden to set or clear flags which are
	 * NOT defined in HSM_USER_MASK. */
	if (((hss->hss_setmask | hss->hss_clearmask) & ~HSM_USER_MASK) &&
	    !md_capable(mdt_ucred(info), CAP_SYS_ADMIN)) {
		CDEBUG(D_HSM, "Incompatible masks provided (set %#llx"
		       ", clear %#llx) vs unprivileged set (%#x).\n",
		       hss->hss_setmask, hss->hss_clearmask, HSM_USER_MASK);
		GOTO(out_unlock, rc = -EPERM);
	}

	/* Read current HSM info */
	ma->ma_valid = 0;
	ma->ma_need = MA_HSM;
	rc = mdt_attr_get_complex(info, obj, ma);
	if (rc)
		GOTO(out_unlock, rc);

	/* Change HSM flags depending on provided masks */
	if (hss->hss_valid & HSS_SETMASK)
		ma->ma_hsm.mh_flags |= hss->hss_setmask;
	if (hss->hss_valid & HSS_CLEARMASK)
		ma->ma_hsm.mh_flags &= ~hss->hss_clearmask;

	/* Change archive_id if provided. */
	if (hss->hss_valid & HSS_ARCHIVE_ID) {
		struct ptlrpc_request *req = mdt_info_req(info);
		struct obd_export *exp = req->rq_export;

		if (!(ma->ma_hsm.mh_flags & HS_EXISTS)) {
			CDEBUG(D_HSM, "Could not set an archive number for "
			       DFID "if HSM EXISTS flag is not set.\n",
			       PFID(&info->mti_body->mbo_fid1));
			GOTO(out_unlock, rc);
		}

		if (!exp_connect_archive_id_array(exp) &&
		    hss->hss_archive_id > LL_HSM_ORIGIN_MAX_ARCHIVE) {
			CDEBUG(D_HSM, "archive id %u from old clients "
			       "exceeds maximum %zu.\n",
			       hss->hss_archive_id, LL_HSM_ORIGIN_MAX_ARCHIVE);
			GOTO(out_unlock, rc = -EINVAL);
		}

		ma->ma_hsm.mh_arch_id = hss->hss_archive_id;
	}

	/* Check for inconsistant HSM flagset.
	 * DIRTY without EXISTS: no dirty if no archive was created.
	 * DIRTY and RELEASED: a dirty file could not be released.
	 * RELEASED without ARCHIVED: do not release a non-archived file.
	 * LOST without ARCHIVED: cannot lost a non-archived file.
	 */
	flags = ma->ma_hsm.mh_flags;
	if ((flags & HS_DIRTY    && !(flags & HS_EXISTS)) ||
	    (flags & HS_RELEASED && flags & HS_DIRTY) ||
	    (flags & HS_RELEASED && !(flags & HS_ARCHIVED)) ||
	    (flags & HS_LOST     && !(flags & HS_ARCHIVED))) {
		CDEBUG(D_HSM, "Incompatible flag change on "DFID
			      "flags=%#llx\n",
		       PFID(&info->mti_body->mbo_fid1), flags);
		GOTO(out_unlock, rc = -EINVAL);
	}

	/* Save the modified flags */
	rc = mdt_hsm_attr_set(info, obj, &ma->ma_hsm);
	if (rc)
		GOTO(out_unlock, rc);

	EXIT;

out_unlock:
	mdt_object_unlock(info, obj, lh, 1);
out_ucred:
	mdt_exit_ucred(info);
out:
	mdt_thread_info_fini(info);
	return rc;
}

/**
 * Retrieve undergoing HSM requests for the fid provided in RPC body.
 * Current requests are read from coordinator states.
 *
 * This is MDS_HSM_ACTION RPC handler.
 */
int mdt_hsm_action(struct tgt_session_info *tsi)
{
	struct mdt_thread_info *info;
	struct hsm_current_action *hca;
	enum hsm_copytool_action action; /* HSMA_* */
	enum agent_req_status status; /* ARS_* */
	struct hsm_extent extent;
	int rc;
	ENTRY;

	hca = req_capsule_server_get(tsi->tsi_pill,
				     &RMF_MDS_HSM_CURRENT_ACTION);
	if (hca == NULL)
		RETURN(err_serious(-EPROTO));

	if (tsi->tsi_mdt_body == NULL)
		RETURN(-EPROTO);

	info = tsi2mdt_info(tsi);
	/* Only valid if client is remote */
	rc = mdt_init_ucred(info, (struct mdt_body *)info->mti_body);
	if (rc < 0)
		GOTO(out, rc = err_serious(rc));

	rc = mdt_hsm_get_action(info, &info->mti_body->mbo_fid1, &action,
				&status, &extent);
	if (rc < 0)
		GOTO(out_ucred, rc);

	switch (action) {
	case HSMA_NONE:
		hca->hca_action = HUA_NONE;
		break;
	case HSMA_ARCHIVE:
		hca->hca_action = HUA_ARCHIVE;
		break;
	case HSMA_RESTORE:
		hca->hca_action = HUA_RESTORE;
		break;
	case HSMA_REMOVE:
		hca->hca_action = HUA_REMOVE;
		break;
	case HSMA_CANCEL:
		hca->hca_action = HUA_CANCEL;
		break;
	default:
		hca->hca_action = HUA_NONE;
		CERROR("%s: Unknown hsm action: %d on "DFID"\n",
		       mdt_obd_name(info->mti_mdt), action,
		       PFID(&info->mti_body->mbo_fid1));
		break;
	}

	switch (status) {
	case ARS_WAITING:
		hca->hca_state = HPS_WAITING;
		break;
	case ARS_STARTED:
		hca->hca_state = HPS_RUNNING;
		break;
	default:
		hca->hca_state = HPS_NONE;
		break;
	}

	hca->hca_location = extent;

	EXIT;
out_ucred:
	mdt_exit_ucred(info);
out:
	mdt_thread_info_fini(info);
	return rc;
}

/* Return true if a FID is present in an action list. */
static bool is_fid_in_hal(struct hsm_action_list *hal, const struct lu_fid *fid)
{
	struct hsm_action_item *hai;
	int i;

	for (hai = hai_first(hal), i = 0;
	     i < hal->hal_count;
	     i++, hai = hai_next(hai)) {
		if (lu_fid_eq(&hai->hai_fid, fid))
			return true;
	}

	return false;
}

/**
 * Process the HSM actions described in a struct hsm_user_request.
 *
 * The action described in hur will be send to coordinator to be saved and
 * processed later or either handled directly if hur.hur_action is HUA_RELEASE.
 *
 * This is MDS_HSM_REQUEST RPC handler.
 */
int mdt_hsm_request(struct tgt_session_info *tsi)
{
	struct mdt_thread_info		*info;
	struct req_capsule		*pill = tsi->tsi_pill;
	struct hsm_request		*hr;
	struct hsm_user_item		*hui;
	struct hsm_action_list		*hal;
	struct hsm_action_item		*hai;
	const void			*data;
	int				 hui_list_size;
	int				 data_size;
	enum hsm_copytool_action	 action = HSMA_NONE;
	int				 hal_size, i, rc;
	ENTRY;

	hr = req_capsule_client_get(pill, &RMF_MDS_HSM_REQUEST);
	hui = req_capsule_client_get(pill, &RMF_MDS_HSM_USER_ITEM);
	data = req_capsule_client_get(pill, &RMF_GENERIC_DATA);

	if (tsi->tsi_mdt_body == NULL || hr == NULL || hui == NULL || data == NULL)
		RETURN(-EPROTO);

	/* Sanity check. Nothing to do with an empty list */
	if (hr->hr_itemcount == 0)
		RETURN(0);

	hui_list_size = req_capsule_get_size(pill, &RMF_MDS_HSM_USER_ITEM,
					     RCL_CLIENT);
	if (hui_list_size < hr->hr_itemcount * sizeof(*hui))
		RETURN(-EPROTO);

	data_size = req_capsule_get_size(pill, &RMF_GENERIC_DATA, RCL_CLIENT);
	if (data_size != hr->hr_data_len)
		RETURN(-EPROTO);

	info = tsi2mdt_info(tsi);
	/* Only valid if client is remote */
	rc = mdt_init_ucred(info, (struct mdt_body *)info->mti_body);
	if (rc)
		GOTO(out, rc);

	switch (hr->hr_action) {
	/* code to be removed in hsm1_merge and final patch */
	case HUA_RELEASE:
		CERROR("Release action is not working in hsm1_coord\n");
		GOTO(out_ucred, rc = -EINVAL);
		break;
	/* end of code to be removed */
	case HUA_ARCHIVE:
		action = HSMA_ARCHIVE;
		break;
	case HUA_RESTORE:
		action = HSMA_RESTORE;
		break;
	case HUA_REMOVE:
		action = HSMA_REMOVE;
		break;
	case HUA_CANCEL:
		action = HSMA_CANCEL;
		break;
	default:
		CERROR("Unknown hsm action: %d\n", hr->hr_action);
		GOTO(out_ucred, rc = -EINVAL);
	}

	hal_size = sizeof(*hal) + cfs_size_round(MTI_NAME_MAXLEN) /* fsname */ +
		   (sizeof(*hai) + cfs_size_round(hr->hr_data_len)) *
		   hr->hr_itemcount;

	MDT_HSM_ALLOC(hal, hal_size);
	if (hal == NULL)
		GOTO(out_ucred, rc = -ENOMEM);

	hal->hal_version = HAL_VERSION;
	hal->hal_archive_id = hr->hr_archive_id;
	hal->hal_flags = hr->hr_flags;
	obd_uuid2fsname(hal->hal_fsname, mdt_obd_name(info->mti_mdt),
			MTI_NAME_MAXLEN);

	hal->hal_count = 0;
	hai = hai_first(hal);
	for (i = 0; i < hr->hr_itemcount; i++, hai = hai_next(hai)) {
		/* Get rid of duplicate entries. Otherwise we get
		 * duplicated work in the llog. */
		if (is_fid_in_hal(hal, &hui[i].hui_fid))
			continue;

		hai->hai_action = action;
		hai->hai_cookie = 0;
		hai->hai_gid = 0;
		hai->hai_fid = hui[i].hui_fid;
		hai->hai_extent = hui[i].hui_extent;
		memcpy(hai->hai_data, data, hr->hr_data_len);
		hai->hai_len = sizeof(*hai) + hr->hr_data_len;

		hal->hal_count++;
	}

	rc = mdt_hsm_add_actions(info, hal);

	MDT_HSM_FREE(hal, hal_size);

	GOTO(out_ucred, rc);

out_ucred:
	mdt_exit_ucred(info);
out:
	mdt_thread_info_fini(info);
	return rc;
}
