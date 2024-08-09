// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2017, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#define DEBUG_SUBSYSTEM S_MDC

#include <linux/module.h>
#include <linux/kernel.h>

#include <obd_class.h>
#include "mdc_internal.h"
#include <lustre_fid.h>

/* mdc_setattr does its own semaphore handling */
static int mdc_reint(struct ptlrpc_request *request, int level)
{
        int rc;

        request->rq_send_state = level;

	ptlrpc_get_mod_rpc_slot(request);
	rc = ptlrpc_queue_wait(request);
	ptlrpc_put_mod_rpc_slot(request);
        if (rc)
                CDEBUG(D_INFO, "error in handling %d\n", rc);
        else if (!req_capsule_server_get(&request->rq_pill, &RMF_MDT_BODY)) {
                rc = -EPROTO;
        }
        return rc;
}

/* Find and cancel locally locks matched by inode @bits & @mode in the resource
 * found by @fid. Found locks are added into @cancel list. Returns the amount of
 * locks added to @cancels list. */
int mdc_resource_get_unused_res(struct obd_export *exp,
				struct ldlm_res_id *res_id,
				struct list_head *cancels,
				enum ldlm_mode mode, __u64 bits)
{
	struct ldlm_namespace *ns = exp->exp_obd->obd_namespace;
	union ldlm_policy_data policy = { { 0 } };
	struct ldlm_resource *res;
	int count;

	ENTRY;

	/* Return, i.e. cancel nothing, only if ELC is supported (flag in
	 * export) but disabled through procfs (flag in NS).
	 *
	 * This distinguishes from a case when ELC is not supported originally,
	 * when we still want to cancel locks in advance and just cancel them
	 * locally, without sending any RPC. */
	if (exp_connect_cancelset(exp) && !ns_connect_cancelset(ns))
		RETURN(0);

	res = ldlm_resource_get(ns, res_id, 0, 0);
	if (IS_ERR(res))
		RETURN(0);
	/* Initialize ibits lock policy. */
	policy.l_inodebits.bits = bits;
	count = ldlm_cancel_resource_local(res, cancels, &policy, mode, 0, 0,
					   NULL);
	ldlm_resource_putref(res);
	RETURN(count);
}

int mdc_resource_get_unused(struct obd_export *exp, const struct lu_fid *fid,
			    struct list_head *cancels, enum ldlm_mode mode,
			    __u64 bits)
{
	struct ldlm_res_id res_id;

	fid_build_reg_res_name(fid, &res_id);
	return mdc_resource_get_unused_res(exp, &res_id, cancels, mode, bits);
}

int mdc_setattr(struct obd_export *exp, struct md_op_data *op_data,
		void *ea, size_t ealen, struct ptlrpc_request **request)
{
	LIST_HEAD(cancels);
        struct ptlrpc_request *req;
        int count = 0, rc;
        __u64 bits;
        ENTRY;

        LASSERT(op_data != NULL);

        bits = MDS_INODELOCK_UPDATE;
        if (op_data->op_attr.ia_valid & (ATTR_MODE|ATTR_UID|ATTR_GID))
                bits |= MDS_INODELOCK_LOOKUP;
	if ((op_data->op_flags & MF_MDC_CANCEL_FID1) &&
	    (fid_is_sane(&op_data->op_fid1)))
		count = mdc_resource_get_unused(exp, &op_data->op_fid1,
						&cancels, LCK_EX, bits);
        req = ptlrpc_request_alloc(class_exp2cliimp(exp),
                                   &RQF_MDS_REINT_SETATTR);
        if (req == NULL) {
                ldlm_lock_list_put(&cancels, l_bl_ast, count);
                RETURN(-ENOMEM);
        }

	req_capsule_set_size(&req->rq_pill, &RMF_MDT_EPOCH, RCL_CLIENT, 0);
	req_capsule_set_size(&req->rq_pill, &RMF_EADATA, RCL_CLIENT, ealen);
	req_capsule_set_size(&req->rq_pill, &RMF_LOGCOOKIES, RCL_CLIENT, 0);

	rc = mdc_prep_elc_req(exp, req, MDS_REINT, &cancels, count);
	if (rc) {
		ptlrpc_request_free(req);
		RETURN(rc);
	}

        if (op_data->op_attr.ia_valid & (ATTR_MTIME | ATTR_CTIME))
		CDEBUG(D_INODE, "setting mtime %lld, ctime %lld\n",
		       (s64)op_data->op_attr.ia_mtime.tv_sec,
		       (s64)op_data->op_attr.ia_ctime.tv_sec);
	mdc_setattr_pack(&req->rq_pill, op_data, ea, ealen);

	req_capsule_set_size(&req->rq_pill, &RMF_ACL, RCL_SERVER, 0);

        ptlrpc_request_set_replen(req);

	rc = mdc_reint(req, LUSTRE_IMP_FULL);
	if (rc == -ERESTARTSYS)
                rc = 0;

        *request = req;

	RETURN(rc);
}

int mdc_create(struct obd_export *exp, struct md_op_data *op_data,
		const void *data, size_t datalen,
		umode_t mode, uid_t uid, gid_t gid,
		kernel_cap_t cap_effective, __u64 rdev,
		struct ptlrpc_request **request)
{
	struct ptlrpc_request *req;
	struct sptlrpc_sepol *sepol;
	int level, rc;
	int count, resends = 0;
	struct obd_import *import = exp->exp_obd->u.cli.cl_import;
	int generation = import->imp_generation;
	LIST_HEAD(cancels);

	ENTRY;

	/* For case if upper layer did not alloc fid, do it now. */
	if (!fid_is_sane(&op_data->op_fid2)) {
		/*
		 * mdc_fid_alloc() may return errno 1 in case of switch to new
		 * sequence, handle this.
		 */
		rc = mdc_fid_alloc(NULL, exp, &op_data->op_fid2, op_data);
		if (rc < 0)
			RETURN(rc);
	}

rebuild:
	count = 0;
	if ((op_data->op_flags & MF_MDC_CANCEL_FID1) &&
	    (fid_is_sane(&op_data->op_fid1)))
		count = mdc_resource_get_unused(exp, &op_data->op_fid1,
						&cancels, LCK_EX,
						MDS_INODELOCK_UPDATE);

	req = ptlrpc_request_alloc(class_exp2cliimp(exp),
				   &RQF_MDS_REINT_CREATE_ACL);
	if (req == NULL) {
		ldlm_lock_list_put(&cancels, l_bl_ast, count);
		RETURN(-ENOMEM);
	}

	req_capsule_set_size(&req->rq_pill, &RMF_NAME, RCL_CLIENT,
			     op_data->op_namelen + 1);
	req_capsule_set_size(&req->rq_pill, &RMF_EADATA, RCL_CLIENT,
			     data && datalen ? datalen : 0);

	req_capsule_set_size(&req->rq_pill, &RMF_FILE_SECCTX_NAME,
			     RCL_CLIENT, op_data->op_file_secctx_name != NULL ?
			     strlen(op_data->op_file_secctx_name) + 1 : 0);

	req_capsule_set_size(&req->rq_pill, &RMF_FILE_SECCTX, RCL_CLIENT,
			     op_data->op_file_secctx_size);

	req_capsule_set_size(&req->rq_pill, &RMF_FILE_ENCCTX, RCL_CLIENT,
			     op_data->op_file_encctx_size);

	/* get SELinux policy info if any */
	sepol = sptlrpc_sepol_get(req);
	if (IS_ERR(sepol))
		GOTO(err_free_rq, rc = PTR_ERR(sepol));

	req_capsule_set_size(&req->rq_pill, &RMF_SELINUX_POL, RCL_CLIENT,
			     sptlrpc_sepol_size(sepol));

	rc = mdc_prep_elc_req(exp, req, MDS_REINT, &cancels, count);
	if (rc)
		GOTO(err_put_sepol, rc);

	/*
	 * mdc_create_pack() fills msg->bufs[1] with name and msg->bufs[2] with
	 * tgt, for symlinks or lov MD data.
	 */
	mdc_create_pack(&req->rq_pill, op_data, data, datalen, mode, uid,
			gid, cap_effective, rdev, sepol);

	sptlrpc_sepol_put(sepol);

	req_capsule_set_size(&req->rq_pill, &RMF_MDT_MD, RCL_SERVER,
			     exp->exp_obd->u.cli.cl_default_mds_easize);
	ptlrpc_request_set_replen(req);

	/* ask ptlrpc not to resend on EINPROGRESS since we have our own retry
	 * logic here */
	req->rq_no_retry_einprogress = 1;

	if (resends) {
		req->rq_generation_set = 1;
		req->rq_import_generation = generation;
		req->rq_sent = ktime_get_real_seconds() + resends;
	}
	level = LUSTRE_IMP_FULL;
 resend:
	rc = mdc_reint(req, level);

	/* Resend if we were told to. */
	if (rc == -ERESTARTSYS) {
		level = LUSTRE_IMP_RECOVER;
		goto resend;
	} else if (rc == -EINPROGRESS) {
		/* Retry create infinitely until succeed or get other
		 * error code or interrupted. */
		ptlrpc_req_put(req);
		if (generation == import->imp_generation) {
			if (signal_pending(current))
				RETURN(-EINTR);

			resends++;
			CDEBUG(D_HA, "%s: resend:%d create on "DFID"/"DFID"\n",
			       exp->exp_obd->obd_name, resends,
			       PFID(&op_data->op_fid1),
			       PFID(&op_data->op_fid2));
			goto rebuild;
		} else {
			CDEBUG(D_HA, "resend cross eviction\n");
			RETURN(-EIO);
		}
	} else if (rc == 0 && S_ISDIR(mode)) {
		struct mdt_body *body;

		body = req_capsule_server_get(&req->rq_pill, &RMF_MDT_BODY);
		if (body == NULL) {
			rc = -EPROTO;
			CERROR("%s: cannot swab mdt_body: rc = %d\n",
			       exp->exp_obd->obd_name, rc);
			RETURN(rc);
		}

		if ((body->mbo_valid & (OBD_MD_FLDIREA | OBD_MD_MEA)) ==
		    (OBD_MD_FLDIREA | OBD_MD_MEA)) {
			void *eadata;

			/* clear valid, because mkdir doesn't need to initialize
			 * LMV, which will be delayed to lookup.
			 */
			body->mbo_valid &= ~(OBD_MD_FLDIREA | OBD_MD_MEA);
			mdc_update_max_ea_from_body(exp, body);
			/* The eadata is opaque; just check that it is there.
			 * Eventually, obd_unpackmd() will check the contents.
			 */
			eadata = req_capsule_server_sized_get(&req->rq_pill,
							  &RMF_MDT_MD,
							  body->mbo_eadatasize);
			if (eadata == NULL)
				RETURN(-EPROTO);

			/* save the reply LMV EA in case we have to replay a
			 * create for recovery.
			 */
			rc = mdc_save_lmm(req, eadata, body->mbo_eadatasize);
		}
	}

	*request = req;

	RETURN(rc);

err_put_sepol:
	sptlrpc_sepol_put(sepol);
err_free_rq:
	ptlrpc_request_free(req);

	RETURN(rc);
}

int mdc_unlink(struct obd_export *exp, struct md_op_data *op_data,
	       struct ptlrpc_request **request)
{
	LIST_HEAD(cancels);
	struct obd_device *obd = class_exp2obd(exp);
	struct ptlrpc_request *req = *request;
	struct sptlrpc_sepol *sepol;
	int count = 0, rc;
	ENTRY;

	LASSERT(req == NULL);

	if ((op_data->op_flags & MF_MDC_CANCEL_FID1) &&
	    (fid_is_sane(&op_data->op_fid1)))
		count = mdc_resource_get_unused(exp, &op_data->op_fid1,
						&cancels, LCK_EX,
						MDS_INODELOCK_UPDATE);
	if ((op_data->op_flags & MF_MDC_CANCEL_FID3) &&
	    (fid_is_sane(&op_data->op_fid3)))
		/* cancel DOM lock only if it has no data to flush */
		count += mdc_resource_get_unused(exp, &op_data->op_fid3,
						 &cancels, LCK_EX,
						 op_data->op_cli_flags &
						 CLI_DIRTY_DATA ?
						 MDS_INODELOCK_ELC :
						 MDS_INODELOCK_FULL);
	req = ptlrpc_request_alloc(class_exp2cliimp(exp),
				   &RQF_MDS_REINT_UNLINK);
	if (req == NULL) {
		ldlm_lock_list_put(&cancels, l_bl_ast, count);
		RETURN(-ENOMEM);
	}

	req_capsule_set_size(&req->rq_pill, &RMF_NAME, RCL_CLIENT,
			     op_data->op_namelen + 1);

	/* get SELinux policy info if any */
	sepol = sptlrpc_sepol_get(req);
	if (IS_ERR(sepol))
		GOTO(err_free_rq, rc = PTR_ERR(sepol));

	req_capsule_set_size(&req->rq_pill, &RMF_SELINUX_POL, RCL_CLIENT,
			     sptlrpc_sepol_size(sepol));

	rc = mdc_prep_elc_req(exp, req, MDS_REINT, &cancels, count);
	if (rc)
		GOTO(err_put_sepol, rc);

	mdc_unlink_pack(&req->rq_pill, op_data, sepol);
	sptlrpc_sepol_put(sepol);

	req_capsule_set_size(&req->rq_pill, &RMF_MDT_MD, RCL_SERVER,
			     obd->u.cli.cl_default_mds_easize);
	ptlrpc_request_set_replen(req);

	*request = req;

	rc = mdc_reint(req, LUSTRE_IMP_FULL);
	if (rc == -ERESTARTSYS)
		rc = 0;

	RETURN(rc);

err_put_sepol:
	sptlrpc_sepol_put(sepol);
err_free_rq:
	ptlrpc_request_free(req);

	RETURN(rc);
}

int mdc_link(struct obd_export *exp, struct md_op_data *op_data,
	     struct ptlrpc_request **request)
{
	LIST_HEAD(cancels);
	struct ptlrpc_request *req;
	struct sptlrpc_sepol *sepol;
	int count = 0, rc;
	ENTRY;

	if ((op_data->op_flags & MF_MDC_CANCEL_FID2) &&
	    (fid_is_sane(&op_data->op_fid2)))
		count = mdc_resource_get_unused(exp, &op_data->op_fid2,
						&cancels, LCK_EX,
						MDS_INODELOCK_UPDATE);
	if ((op_data->op_flags & MF_MDC_CANCEL_FID1) &&
	    (fid_is_sane(&op_data->op_fid1)))
		count += mdc_resource_get_unused(exp, &op_data->op_fid1,
						 &cancels, LCK_EX,
						 MDS_INODELOCK_UPDATE);

	req = ptlrpc_request_alloc(class_exp2cliimp(exp), &RQF_MDS_REINT_LINK);
	if (req == NULL) {
		ldlm_lock_list_put(&cancels, l_bl_ast, count);
		RETURN(-ENOMEM);
	}

	req_capsule_set_size(&req->rq_pill, &RMF_NAME, RCL_CLIENT,
			     op_data->op_namelen + 1);

	/* get SELinux policy info if any */
	sepol = sptlrpc_sepol_get(req);
	if (IS_ERR(sepol))
		GOTO(err_free_rq, rc = PTR_ERR(sepol));

	req_capsule_set_size(&req->rq_pill, &RMF_SELINUX_POL, RCL_CLIENT,
			     sptlrpc_sepol_size(sepol));

	rc = mdc_prep_elc_req(exp, req, MDS_REINT, &cancels, count);
	if (rc)
		GOTO(err_put_sepol, rc);

	mdc_link_pack(&req->rq_pill, op_data, sepol);
	sptlrpc_sepol_put(sepol);

	ptlrpc_request_set_replen(req);

	rc = mdc_reint(req, LUSTRE_IMP_FULL);
	*request = req;
	if (rc == -ERESTARTSYS)
		rc = 0;

	RETURN(rc);

err_put_sepol:
	sptlrpc_sepol_put(sepol);
err_free_rq:
	ptlrpc_request_free(req);

	RETURN(rc);
}

int mdc_rename(struct obd_export *exp, struct md_op_data *op_data,
		const char *old, size_t oldlen, const char *new, size_t newlen,
		struct ptlrpc_request **request)
{
	LIST_HEAD(cancels);
	struct obd_device *obd = exp->exp_obd;
	struct ptlrpc_request *req;
	struct sptlrpc_sepol *sepol;
	int count = 0, rc;

	ENTRY;

	if ((op_data->op_flags & MF_MDC_CANCEL_FID1) &&
	    (fid_is_sane(&op_data->op_fid1)))
		count = mdc_resource_get_unused(exp, &op_data->op_fid1,
						&cancels, LCK_EX,
						MDS_INODELOCK_UPDATE);
	if ((op_data->op_flags & MF_MDC_CANCEL_FID2) &&
	    (fid_is_sane(&op_data->op_fid2)))
		count += mdc_resource_get_unused(exp, &op_data->op_fid2,
						 &cancels, LCK_EX,
						 MDS_INODELOCK_UPDATE);
	if ((op_data->op_flags & MF_MDC_CANCEL_FID3) &&
	    (fid_is_sane(&op_data->op_fid3)))
		count += mdc_resource_get_unused(exp, &op_data->op_fid3,
						 &cancels, LCK_EX,
						 MDS_INODELOCK_LOOKUP);
	if ((op_data->op_flags & MF_MDC_CANCEL_FID4) &&
	    (fid_is_sane(&op_data->op_fid4)))
		count += mdc_resource_get_unused(exp, &op_data->op_fid4,
						 &cancels, LCK_EX,
						 MDS_INODELOCK_ELC);

	req = ptlrpc_request_alloc(class_exp2cliimp(exp),
			   op_data->op_cli_flags & CLI_MIGRATE ?
			   &RQF_MDS_REINT_MIGRATE : &RQF_MDS_REINT_RENAME);
	if (req == NULL) {
		ldlm_lock_list_put(&cancels, l_bl_ast, count);
		RETURN(-ENOMEM);
	}

	req_capsule_set_size(&req->rq_pill, &RMF_NAME, RCL_CLIENT, oldlen + 1);
	req_capsule_set_size(&req->rq_pill, &RMF_SYMTGT, RCL_CLIENT, newlen+1);
	if (op_data->op_cli_flags & CLI_MIGRATE)
		req_capsule_set_size(&req->rq_pill, &RMF_EADATA, RCL_CLIENT,
				     op_data->op_data_size);

	/* get SELinux policy info if any */
	sepol = sptlrpc_sepol_get(req);
	if (IS_ERR(sepol))
		GOTO(err_free_rq, rc = PTR_ERR(sepol));

	req_capsule_set_size(&req->rq_pill, &RMF_SELINUX_POL, RCL_CLIENT,
			     sptlrpc_sepol_size(sepol));

	rc = mdc_prep_elc_req(exp, req, MDS_REINT, &cancels, count);
	if (rc)
		GOTO(err_put_sepol, rc);

	if (exp_connect_cancelset(exp) && req)
		ldlm_cli_cancel_list(&cancels, count, req, 0);

	if (op_data->op_cli_flags & CLI_MIGRATE)
		mdc_migrate_pack(&req->rq_pill, op_data, old, oldlen);
	else
		mdc_rename_pack(&req->rq_pill, op_data, old, oldlen,
				new, newlen, sepol);

	sptlrpc_sepol_put(sepol);

	/* LU-17441: avoid blocking MDS_REQUEST_PORTAL for renames with BFL */
#if LUSTRE_VERSION_CODE < OBD_OCD_VERSION(2, 20, 53, 0)
	/* MDS_IO_PORTAL available since v2_10_53_0-33-g2bcc5ad0ed */
	if ((exp_connect_flags(exp) &
	     (OBD_CONNECT_GRANT | OBD_CONNECT_SRVLOCK)) ==
	    (OBD_CONNECT_GRANT | OBD_CONNECT_SRVLOCK))
#endif
		req->rq_request_portal = MDS_IO_PORTAL;
	req_capsule_set_size(&req->rq_pill, &RMF_MDT_MD, RCL_SERVER,
			     obd->u.cli.cl_default_mds_easize);
	ptlrpc_request_set_replen(req);

	rc = mdc_reint(req, LUSTRE_IMP_FULL);
	*request = req;
	if (rc == -ERESTARTSYS)
		rc = 0;

	RETURN(rc);

err_put_sepol:
	sptlrpc_sepol_put(sepol);
err_free_rq:
	ptlrpc_request_free(req);

	RETURN(rc);
}

int mdc_file_resync(struct obd_export *exp, struct md_op_data *op_data)
{
	LIST_HEAD(cancels);
	struct ptlrpc_request *req;
	struct ldlm_lock *lock;
	struct mdt_rec_resync *rec;
	int count = 0, rc;
	ENTRY;

	if (op_data->op_flags & MF_MDC_CANCEL_FID1 &&
	    fid_is_sane(&op_data->op_fid1))
		count = mdc_resource_get_unused(exp, &op_data->op_fid1,
						&cancels, LCK_EX,
						MDS_INODELOCK_LAYOUT);

	req = ptlrpc_request_alloc(class_exp2cliimp(exp),
				   &RQF_MDS_REINT_RESYNC);
	if (req == NULL) {
		ldlm_lock_list_put(&cancels, l_bl_ast, count);
		RETURN(-ENOMEM);
	}

	rc = mdc_prep_elc_req(exp, req, MDS_REINT, &cancels, count);
	if (rc) {
		ptlrpc_request_free(req);
		RETURN(rc);
	}

	BUILD_BUG_ON(sizeof(*rec) != sizeof(struct mdt_rec_reint));
	rec = req_capsule_client_get(&req->rq_pill, &RMF_REC_REINT);
	rec->rs_opcode	= REINT_RESYNC;
	rec->rs_fsuid	= op_data->op_fsuid;
	rec->rs_fsgid	= op_data->op_fsgid;
	rec->rs_cap	= ll_capability_u32(op_data->op_cap);
	rec->rs_fid	= op_data->op_fid1;
	rec->rs_bias	= op_data->op_bias;
	if (exp_connect_mirror_id_fix(exp))
		rec->rs_mirror_id_new = op_data->op_mirror_id;
	else
		rec->rs_mirror_id_old = op_data->op_mirror_id;

	lock = ldlm_handle2lock(&op_data->op_lease_handle);
	if (lock != NULL) {
		rec->rs_lease_handle = lock->l_remote_handle;
		ldlm_lock_put(lock);
	}

	ptlrpc_request_set_replen(req);

	rc = mdc_reint(req, LUSTRE_IMP_FULL);
	if (rc == -ERESTARTSYS)
		rc = 0;

	ptlrpc_req_put(req);
	RETURN(rc);
}
