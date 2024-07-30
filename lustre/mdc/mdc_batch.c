// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2020, 2022, DDN Storage Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Batch Metadata Updating on the client (MDC)
 *
 * Author: Qian Yingjin <qian@ddn.com>
 */

#define DEBUG_SUBSYSTEM S_MDC

#include <linux/module.h>
#include <lustre_acl.h>

#include "mdc_internal.h"

static int mdc_ldlm_lock_pack(struct obd_export *exp,
			      struct req_capsule *pill,
			      union ldlm_policy_data *policy,
			      struct lu_fid *fid, struct md_op_item *item)
{
	struct ldlm_request *dlmreq;
	struct ldlm_res_id res_id;
	struct ldlm_enqueue_info *einfo = &item->mop_einfo;
	int rc;

	ENTRY;

	dlmreq = req_capsule_client_get(pill, &RMF_DLM_REQ);
	if (IS_ERR(dlmreq))
		RETURN(PTR_ERR(dlmreq));

	/* With Data-on-MDT the glimpse callback is needed too.
	 * It is set here in advance but not in mdc_finish_enqueue()
	 * to avoid possible races. It is safe to have glimpse handler
	 * for non-DOM locks and costs nothing.
	 */
	if (einfo->ei_cb_gl == NULL)
		einfo->ei_cb_gl = mdc_ldlm_glimpse_ast;

	fid_build_reg_res_name(fid, &res_id);
	rc = ldlm_cli_lock_create_pack(exp, dlmreq, einfo, &res_id,
				       policy, &item->mop_lock_flags,
				       NULL, 0, LVB_T_NONE, &item->mop_lockh);

	RETURN(rc);
}

static int mdc_batch_getattr_pack(struct batch_update_head *head,
				  struct lustre_msg *reqmsg,
				  size_t *max_pack_size,
				  struct md_op_item *item)
{
	struct obd_export *exp = head->buh_exp;
	struct lookup_intent *it = &item->mop_it;
	struct md_op_data *op_data = &item->mop_data;
	u64 valid = OBD_MD_FLGETATTR | OBD_MD_FLEASIZE | OBD_MD_FLMODEASIZE |
		    OBD_MD_FLDIREA | OBD_MD_MEA | OBD_MD_FLACL |
		    OBD_MD_DEFAULT_MEA;
	union ldlm_policy_data policy = {
		.l_inodebits = { MDS_INODELOCK_LOOKUP | MDS_INODELOCK_UPDATE }
	};
	struct ldlm_intent *lit;
	bool have_secctx = false;
	struct req_capsule pill;
	__u32 easize;
	__u32 size;
	int rc;

	ENTRY;

	req_capsule_subreq_init(&pill, &RQF_BUT_GETATTR, NULL,
				reqmsg, NULL, RCL_CLIENT);

	/* send name of security xattr to get upon intent */
	if (it->it_op & (IT_LOOKUP | IT_GETATTR) &&
	    req_capsule_has_field(&pill, &RMF_FILE_SECCTX_NAME,
				  RCL_CLIENT) &&
	    op_data->op_file_secctx_name_size > 0 &&
	    op_data->op_file_secctx_name != NULL) {
		have_secctx = true;
		req_capsule_set_size(&pill, &RMF_FILE_SECCTX_NAME, RCL_CLIENT,
				     op_data->op_file_secctx_name_size);
	}

	req_capsule_set_size(&pill, &RMF_NAME, RCL_CLIENT,
			     op_data->op_namelen + 1);

	size = req_capsule_msg_size(&pill, RCL_CLIENT);
	if (unlikely(size >= *max_pack_size)) {
		*max_pack_size = size;
		return -E2BIG;
	}

	req_capsule_client_pack(&pill);
	/* pack the intent */
	lit = req_capsule_client_get(&pill, &RMF_LDLM_INTENT);
	lit->opc = (__u64)it->it_op;

	easize = MAX_MD_SIZE_OLD; /* obd->u.cli.cl_default_mds_easize; */

	/* pack the intended request */
	mdc_getattr_pack(&pill, valid, it->it_open_flags, op_data, easize);

	item->mop_lock_flags |= LDLM_FL_HAS_INTENT;
	rc = mdc_ldlm_lock_pack(head->buh_exp, &pill, &policy,
				&item->mop_data.op_fid1, item);
	if (rc)
		RETURN(rc);

	req_capsule_set_size(&pill, &RMF_MDT_MD, RCL_SERVER, easize);
	req_capsule_set_size(&pill, &RMF_ACL, RCL_SERVER,
			     LUSTRE_POSIX_ACL_MAX_SIZE_OLD);
	req_capsule_set_size(&pill, &RMF_DEFAULT_MDT_MD, RCL_SERVER,
			     /*sizeof(struct lmv_user_md)*/MIN_MD_SIZE);

	if (have_secctx) {
		char *secctx_name;

		secctx_name = req_capsule_client_get(&pill,
						     &RMF_FILE_SECCTX_NAME);
		memcpy(secctx_name, op_data->op_file_secctx_name,
		       op_data->op_file_secctx_name_size);

		req_capsule_set_size(&pill, &RMF_FILE_SECCTX,
				     RCL_SERVER, easize);

		CDEBUG(D_SEC, "packed '%.*s' as security xattr name\n",
		       op_data->op_file_secctx_name_size,
		       op_data->op_file_secctx_name);
	} else {
		req_capsule_set_size(&pill, &RMF_FILE_SECCTX, RCL_SERVER, 0);
	}

	if (exp_connect_encrypt(exp) && it->it_op & (IT_LOOKUP | IT_GETATTR))
		req_capsule_set_size(&pill, &RMF_FILE_ENCCTX,
				     RCL_SERVER, easize);
	else
		req_capsule_set_size(&pill, &RMF_FILE_ENCCTX,
				     RCL_SERVER, 0);

	req_capsule_set_replen(&pill);
	reqmsg->lm_opc = BUT_GETATTR;
	*max_pack_size = size;
	RETURN(rc);
}

static md_update_pack_t mdc_update_packers[MD_OP_MAX] = {
	[MD_OP_GETATTR]	= mdc_batch_getattr_pack,
};

static int mdc_batch_getattr_interpret(struct ptlrpc_request *req,
				       struct lustre_msg *repmsg,
				       struct object_update_callback *ouc,
				       int rc)
{
	struct md_op_item *item = (struct md_op_item *)ouc->ouc_data;
	struct ldlm_enqueue_info *einfo = &item->mop_einfo;
	struct batch_update_head *head = ouc->ouc_head;
	struct obd_export *exp = head->buh_exp;
	struct req_capsule *pill = item->mop_pill;
	struct ldlm_reply *lockrep;

	req_capsule_subreq_init(pill, &RQF_BUT_GETATTR, req,
				NULL, repmsg, RCL_CLIENT);

	rc = ldlm_cli_enqueue_fini(exp, pill, einfo, 1, &item->mop_lock_flags,
				   NULL, 0, &item->mop_lockh, rc, false);
	if (rc)
		GOTO(out, rc);

	lockrep = req_capsule_server_get(pill, &RMF_DLM_REP);
	LASSERT(lockrep != NULL);

	lockrep->lock_policy_res2 =
		ptlrpc_status_ntoh(lockrep->lock_policy_res2);

	rc = mdc_finish_enqueue(exp, pill, einfo, &item->mop_it,
				&item->mop_lockh, rc);
out:
	return item->mop_cb(item, rc);
}

object_update_interpret_t mdc_update_interpreters[MD_OP_MAX] = {
	[MD_OP_GETATTR]	= mdc_batch_getattr_interpret,
};

int mdc_batch_add(struct obd_export *exp, struct lu_batch *bh,
		  struct md_op_item *item)
{
	enum md_item_opcode opc = item->mop_opc;

	ENTRY;

	if (opc >= MD_OP_MAX || mdc_update_packers[opc] == NULL ||
	    mdc_update_interpreters[opc] == NULL) {
		CERROR("%s: unexpected opcode %d\n",
		       exp->exp_obd->obd_name, opc);
		RETURN(-EFAULT);
	}

	OBD_ALLOC_PTR(item->mop_pill);
	if (item->mop_pill == NULL)
		RETURN(-ENOMEM);

	item->mop_subpill_allocated = 1;
	RETURN(cli_batch_add(exp, bh, item, mdc_update_packers[opc],
			     mdc_update_interpreters[opc]));
}
