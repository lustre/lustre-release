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
 * Copyright (c) 2012, Intel Corporation.
 * Use is subject to license terms.
 * Copyright (c) 2011, 2012 Commissariat a l'energie atomique et aux energies
 *                          alternatives
 */
/*
 * lustre/mdt/mdt_hsm.c
 *
 * Lustre Metadata Target (mdt) request handler
 *
 * Author: Aurelien Degremont <aurelien.degremont@cea.fr>
 * Author: JC Lafoucriere <jacques-charles.lafoucriere@cea.fr>
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_MDS

#include "mdt_internal.h"

/*
 * fake functions, will be replace by real one with HSM Coordinator patch
 */

int mdt_hsm_copytool_send(struct obd_export *exp)
{
	return 0;
}

static int mdt_hsm_coordinator_update(struct mdt_thread_info *info,
				      struct hsm_progress_kernel *pgs)
{
	return 0;
}

static int mdt_hsm_agent_register_mask(struct mdt_thread_info *info,
				       struct obd_uuid *uuid,
				       __u32 archive_mask)
{
	return 0;
}

static int mdt_hsm_agent_unregister(struct mdt_thread_info *info,
				    struct obd_uuid *uuid)
{
	return 0;
}

/**
 * Update on-disk HSM attributes.
 */
int mdt_hsm_attr_set(struct mdt_thread_info *info, struct mdt_object *obj,
		     struct md_hsm *mh)
{
	struct md_object	*next = mdt_object_child(obj);
	struct lu_buf		*buf = &info->mti_buf;
	struct hsm_attrs	*attrs;
	int			 rc;
	ENTRY;

	attrs = (struct hsm_attrs *)info->mti_xattr_buf;
	CLASSERT(sizeof(info->mti_xattr_buf) >= sizeof(*attrs));

	/* pack HSM attributes */
	lustre_hsm2buf(info->mti_xattr_buf, mh);

	/* update SOM attributes */
	buf->lb_buf = attrs;
	buf->lb_len = sizeof(*attrs);
	rc = mo_xattr_set(info->mti_env, next, buf, XATTR_NAME_HSM, 0);

	RETURN(rc);
}

/**
 * Extract information coming from a copytool and asks coordinator to update
 * a request status depending on the update content.
 *
 * Copytools could use this to report failure in their process.
 *
 * This is HSM_PROGRESS RPC handler.
 */
int mdt_hsm_progress(struct mdt_thread_info *info)
{
	struct hsm_progress_kernel	*hpk;
	int				 rc;
	ENTRY;

	hpk = req_capsule_client_get(info->mti_pill, &RMF_MDS_HSM_PROGRESS);
	LASSERT(hpk);

	CDEBUG(D_HSM, "Progress on "DFID": len="LPU64" err=%d\n",
	       PFID(&hpk->hpk_fid), hpk->hpk_extent.length, hpk->hpk_errval);

	if (hpk->hpk_errval)
		CDEBUG(D_HSM, "Copytool progress on "DFID" failed (%d); %s.\n",
		       PFID(&hpk->hpk_fid), hpk->hpk_errval,
		       hpk->hpk_flags & HP_FLAG_RETRY ? "will retry" : "fatal");

	if (hpk->hpk_flags & HP_FLAG_COMPLETED)
		CDEBUG(D_HSM, "Finished "DFID" (%d) cancel cookie="LPX64"\n",
		       PFID(&hpk->hpk_fid), hpk->hpk_errval, hpk->hpk_cookie);

	rc = mdt_hsm_coordinator_update(info, hpk);

	RETURN(rc);
}

int mdt_hsm_ct_register(struct mdt_thread_info *info)
{
	struct ptlrpc_request *req = mdt_info_req(info);
	__u32 *archives;
	int rc;
	ENTRY;

	archives = req_capsule_client_get(info->mti_pill, &RMF_MDS_HSM_ARCHIVE);
	LASSERT(archives);

	/* XXX: directly include this function here? */
	rc = mdt_hsm_agent_register_mask(info, &req->rq_export->exp_client_uuid,
					 *archives);

	RETURN(rc);
}

int mdt_hsm_ct_unregister(struct mdt_thread_info *info)
{
	struct ptlrpc_request *req = mdt_info_req(info);
	int rc;
	ENTRY;

	/* XXX: directly include this function here? */
	rc = mdt_hsm_agent_unregister(info, &req->rq_export->exp_client_uuid);

	RETURN(rc);
}
