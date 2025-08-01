// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2013, 2017, Intel Corporation.
 */

/*
 * Lustre Unified Target request handler code
 *
 * Author: Brian Behlendorf <behlendorf1@llnl.gov>
 * Author: Mikhail Pershin <mike.pershin@intel.com>
 */

#define DEBUG_SUBSYSTEM S_CLASS

#include <linux/user_namespace.h>
#include <linux/delay.h>
#include <linux/uidgid.h>

#include <libcfs/linux/linux-mem.h>
#include <obd.h>
#include <obd_class.h>
#include <obd_cksum.h>
#include <lustre_lfsck.h>
#include <lustre_nodemap.h>
#include <lustre_acl.h>

#include "tgt_internal.h"

char *tgt_name(struct lu_target *tgt)
{
	LASSERT(tgt->lut_obd != NULL);
	return tgt->lut_obd->obd_name;
}
EXPORT_SYMBOL(tgt_name);

/*
 * Generic code handling requests that have struct mdt_body passed in:
 *
 *  - extract mdt_body from request and save it in @tsi, if present;
 *
 *  - create lu_object, corresponding to the fid in mdt_body, and save it in
 *  @tsi;
 *
 *  - if HAS_BODY flag is set for this request type check whether object
 *  actually exists on storage (lu_object_exists()).
 *
 */
static int tgt_mdt_body_unpack(struct tgt_session_info *tsi, __u32 flags)
{
	const struct mdt_body	*body;
	struct lu_object	*obj;
	struct req_capsule	*pill = tsi->tsi_pill;
	int			 rc;

	ENTRY;

	body = req_capsule_client_get(pill, &RMF_MDT_BODY);
	if (body == NULL)
		RETURN(-EFAULT);

	tsi->tsi_mdt_body = body;

	if (!(body->mbo_valid & OBD_MD_FLID))
		RETURN(0);

	/* mdc_pack_body() doesn't check if fid is zero and set OBD_ML_FID
	 * in any case in pre-2.5 clients. Fix that here if needed */
	if (unlikely(fid_is_zero(&body->mbo_fid1)))
		RETURN(0);

	if (!fid_is_sane(&body->mbo_fid1)) {
		CERROR("%s: invalid FID: "DFID"\n", tgt_name(tsi->tsi_tgt),
		       PFID(&body->mbo_fid1));
		RETURN(-EINVAL);
	}

	obj = lu_object_find(tsi->tsi_env,
			     &tsi->tsi_tgt->lut_bottom->dd_lu_dev,
			     &body->mbo_fid1, NULL);
	if (!IS_ERR(obj)) {
		if ((flags & HAS_BODY) && !lu_object_exists(obj)) {
			lu_object_put(tsi->tsi_env, obj);
			rc = -ENOENT;
		} else {
			tsi->tsi_corpus = obj;
			rc = 0;
		}
	} else {
		rc = PTR_ERR(obj);
	}

	tsi->tsi_fid = body->mbo_fid1;

	RETURN(rc);
}

/**
 * Validate oa from client.
 * If the request comes from 2.0 clients, currently only RSVD seq and IDIF
 * req are valid.
 *    a. objects in Single MDT FS  seq = FID_SEQ_OST_MDT0, oi_id != 0
 *    b. Echo objects(seq = 2), old echo client still use oi_id/oi_seq to
 *       pack ost_id. Because non-zero oi_seq will make it diffcult to tell
 *       whether this is oi_fid or real ostid. So it will check
 *       OBD_CONNECT_FID, then convert the ostid to FID for old client.
 *    c. Old FID-disable osc will send IDIF.
 *    d. new FID-enable osc/osp will send normal FID.
 *
 * And also oi_id/f_oid should always start from 1. oi_id/f_oid = 0 will
 * be used for LAST_ID file, and only being accessed inside OST now.
 */
int tgt_validate_obdo(struct tgt_session_info *tsi, struct obdo *oa)
{
	struct ost_id	*oi	= &oa->o_oi;
	u64		 seq	= ostid_seq(oi);
	u64		 id	= ostid_id(oi);
	int		 rc;
	ENTRY;

	if (unlikely(!(exp_connect_flags(tsi->tsi_exp) & OBD_CONNECT_FID) &&
		     fid_seq_is_echo(seq))) {
		/* Sigh 2.[123] client still sends echo req with oi_id = 0
		 * during create, and we will reset this to 1, since this
		 * oi_id is basically useless in the following create process,
		 * but oi_id == 0 will make it difficult to tell whether it is
		 * real FID or ost_id. */
		oi->oi_fid.f_seq = FID_SEQ_ECHO;
		oi->oi_fid.f_oid = id ?: 1;
		oi->oi_fid.f_ver = 0;
	} else {
		struct tgt_thread_info *tti = tgt_th_info(tsi->tsi_env);

		if (unlikely((oa->o_valid & OBD_MD_FLID) && id == 0))
			GOTO(out, rc = -EPROTO);

		/* Note: this check might be forced in 2.5 or 2.6, i.e.
		 * all of the requests are required to setup FLGROUP */
		if (unlikely(!(oa->o_valid & OBD_MD_FLGROUP)))
			oa->o_valid |= OBD_MD_FLGROUP;

		if (unlikely(!(fid_seq_is_idif(seq) || fid_seq_is_mdt0(seq) ||
			       fid_seq_is_norm(seq) || fid_seq_is_echo(seq))))
			GOTO(out, rc = -EPROTO);

		rc = ostid_to_fid(&tti->tti_fid1, oi,
				  tsi->tsi_tgt->lut_lsd.lsd_osd_index);
		if (unlikely(rc != 0))
			GOTO(out, rc);

		oi->oi_fid = tti->tti_fid1;
	}

	RETURN(0);

out:
	CERROR("%s: client %s sent bad object "DOSTID": rc = %d\n",
	       tgt_name(tsi->tsi_tgt), obd_export_nid2str(tsi->tsi_exp),
	       seq, id, rc);
	return rc;
}
EXPORT_SYMBOL(tgt_validate_obdo);

static int tgt_io_data_unpack(struct tgt_session_info *tsi, struct ost_id *oi)
{
	unsigned		 max_brw;
	struct niobuf_remote	*rnb;
	struct obd_ioobj	*ioo;
	int			 obj_count;

	ENTRY;

	ioo = req_capsule_client_get(tsi->tsi_pill, &RMF_OBD_IOOBJ);
	if (ioo == NULL)
		RETURN(-EPROTO);

	rnb = req_capsule_client_get(tsi->tsi_pill, &RMF_NIOBUF_REMOTE);
	if (rnb == NULL)
		RETURN(-EPROTO);

	max_brw = ioobj_max_brw_get(ioo);
	if (unlikely((max_brw & (max_brw - 1)) != 0)) {
		CERROR("%s: client %s sent bad ioobj max %u for "DOSTID
		       ": rc = %d\n", tgt_name(tsi->tsi_tgt),
		       obd_export_nid2str(tsi->tsi_exp), max_brw,
		       POSTID(oi), -EPROTO);
		RETURN(-EPROTO);
	}
	ioo->ioo_oid = *oi;

	obj_count = req_capsule_get_size(tsi->tsi_pill, &RMF_OBD_IOOBJ,
					RCL_CLIENT) / sizeof(*ioo);
	if (obj_count == 0) {
		CERROR("%s: short ioobj\n", tgt_name(tsi->tsi_tgt));
		RETURN(-EPROTO);
	} else if (obj_count > 1) {
		CERROR("%s: too many ioobjs (%d)\n", tgt_name(tsi->tsi_tgt),
		       obj_count);
		RETURN(-EPROTO);
	}

	if (ioo->ioo_bufcnt == 0) {
		CERROR("%s: ioo has zero bufcnt\n", tgt_name(tsi->tsi_tgt));
		RETURN(-EPROTO);
	}

	if (ioo->ioo_bufcnt > PTLRPC_MAX_BRW_PAGES) {
		DEBUG_REQ(D_RPCTRACE, tgt_ses_req(tsi),
			  "bulk has too many pages (%d)",
			  ioo->ioo_bufcnt);
		RETURN(-EPROTO);
	}

	RETURN(0);
}

static int tgt_ost_body_unpack(struct tgt_session_info *tsi, __u32 flags)
{
	struct ost_body		*body;
	struct req_capsule	*pill = tsi->tsi_pill;
	struct lu_nodemap	*nodemap;
	int			 rc;

	ENTRY;

	body = req_capsule_client_get(pill, &RMF_OST_BODY);
	if (body == NULL)
		RETURN(-EFAULT);

	rc = tgt_validate_obdo(tsi, &body->oa);
	if (rc)
		RETURN(rc);

	nodemap = nodemap_get_from_exp(tsi->tsi_exp);
	if (IS_ERR(nodemap))
		RETURN(PTR_ERR(nodemap));

	body->oa.o_uid = nodemap_map_id(nodemap, NODEMAP_UID,
					NODEMAP_CLIENT_TO_FS,
					body->oa.o_uid);
	body->oa.o_gid = nodemap_map_id(nodemap, NODEMAP_GID,
					NODEMAP_CLIENT_TO_FS,
					body->oa.o_gid);
	body->oa.o_projid = nodemap_map_id(nodemap, NODEMAP_PROJID,
					   NODEMAP_CLIENT_TO_FS,
					   body->oa.o_projid);
	nodemap_putref(nodemap);

	tsi->tsi_ost_body = body;
	tsi->tsi_fid = body->oa.o_oi.oi_fid;

	if (req_capsule_has_field(pill, &RMF_OBD_IOOBJ, RCL_CLIENT)) {
		rc = tgt_io_data_unpack(tsi, &body->oa.o_oi);
		if (rc < 0)
			RETURN(rc);
	}

	if (!(body->oa.o_valid & OBD_MD_FLID)) {
		if (flags & HAS_BODY) {
			CERROR("%s: OBD_MD_FLID flag is not set in ost_body but OID/FID is mandatory with HAS_BODY\n",
			       tgt_name(tsi->tsi_tgt));
			RETURN(-EPROTO);
		} else {
			RETURN(0);
		}
	}

	ost_fid_build_resid(&tsi->tsi_fid, &tsi->tsi_resid);

	/*
	 * OST doesn't get object in advance for further use to prevent
	 * situations with nested object_find which is potential deadlock.
	 */
	tsi->tsi_corpus = NULL;
	RETURN(rc);
}

/*
 * Do necessary preprocessing according to handler ->th_flags.
 */
static int tgt_request_preprocess(struct tgt_session_info *tsi,
				  struct tgt_handler *h,
				  struct ptlrpc_request *req)
{
	struct req_capsule	*pill = tsi->tsi_pill;
	__u32			 flags = h->th_flags;
	int			 rc = 0;

	ENTRY;

	if (tsi->tsi_preprocessed)
		RETURN(0);

	LASSERT(h->th_act != NULL);
	LASSERT(h->th_opc == lustre_msg_get_opc(req->rq_reqmsg));
	LASSERT(current->journal_info == NULL);

	LASSERT(ergo(flags & (HAS_BODY | HAS_REPLY),
		     h->th_fmt != NULL));
	if (h->th_fmt != NULL) {
		req_capsule_set(pill, h->th_fmt);
		if (req_capsule_has_field(pill, &RMF_MDT_BODY, RCL_CLIENT) &&
		    req_capsule_field_present(pill, &RMF_MDT_BODY,
					      RCL_CLIENT)) {
			rc = tgt_mdt_body_unpack(tsi, flags);
			if (rc < 0)
				RETURN(rc);
		} else if (req_capsule_has_field(pill, &RMF_OST_BODY,
						 RCL_CLIENT) &&
			   req_capsule_field_present(pill, &RMF_OST_BODY,
						 RCL_CLIENT)) {
			rc = tgt_ost_body_unpack(tsi, flags);
			if (rc < 0)
				RETURN(rc);
		}
	}

	if (flags & IS_MUTABLE && tgt_conn_flags(tsi) & OBD_CONNECT_RDONLY)
		RETURN(-EROFS);

	if (flags & HAS_KEY) {
		struct ldlm_request *dlm_req;

		LASSERT(h->th_fmt != NULL);

		dlm_req = req_capsule_client_get(pill, &RMF_DLM_REQ);
		if (dlm_req != NULL) {
			union ldlm_wire_policy_data *policy =
					&dlm_req->lock_desc.l_policy_data;

			if (unlikely(dlm_req->lock_desc.l_resource.lr_type ==
				     LDLM_IBITS &&
				     (policy->l_inodebits.bits |
				      policy->l_inodebits.try_bits) ==
						MDS_INODELOCK_NONE)) {
				/*
				 * Lock without inodebits makes no sense and
				 * will oops later in ldlm. If client miss to
				 * set such bits, do not trigger ASSERTION.
				 *
				 * For liblustre flock case, it maybe zero.
				 */
				rc = -EPROTO;
			} else {
				tsi->tsi_dlm_req = dlm_req;
			}
		} else {
			rc = -EFAULT;
		}
	}
	tsi->tsi_preprocessed = 1;
	RETURN(rc);
}

/*
 * Invoke handler for this request opc. Also do necessary preprocessing
 * (according to handler ->th_flags), and post-processing (setting of
 * ->last_{xid,committed}).
 */
static int tgt_handle_request0(struct tgt_session_info *tsi,
			       struct tgt_handler *h,
			       struct ptlrpc_request *req)
{
	int	 serious = 0;
	int	 rc;
	__u32    opc = lustre_msg_get_opc(req->rq_reqmsg);

	ENTRY;


	/* When dealing with sec context requests, no export is associated yet,
	 * because these requests are sent before *_CONNECT requests.
	 * A NULL req->rq_export means the normal *_common_slice handlers will
	 * not be called, because there is no reference to the target.
	 * So deal with them by hand and jump directly to target_send_reply().
	 */
	switch (opc) {
	case SEC_CTX_INIT:
	case SEC_CTX_INIT_CONT:
	case SEC_CTX_FINI:
		CFS_FAIL_TIMEOUT(OBD_FAIL_SEC_CTX_HDL_PAUSE, cfs_fail_val);
		GOTO(out, rc = 0);
	}

	/*
	 * Checking for various OBD_FAIL_$PREF_$OPC_NET codes. _Do_ not try
	 * to put same checks into handlers like mdt_close(), mdt_reint(),
	 * etc., without talking to mdt authors first. Checking same thing
	 * there again is useless and returning 0 error without packing reply
	 * is buggy! Handlers either pack reply or return error.
	 *
	 * We return 0 here and do not send any reply in order to emulate
	 * network failure. Do not send any reply in case any of NET related
	 * fail_id has occured.
	 */
	if (CFS_FAIL_CHECK_ORSET(h->th_fail_id, CFS_FAIL_ONCE))
		RETURN(0);
	if (unlikely(lustre_msg_get_opc(req->rq_reqmsg) == MDS_REINT &&
		     CFS_FAIL_CHECK(OBD_FAIL_MDS_REINT_MULTI_NET)))
		RETURN(0);

	/* drop OUT_UPDATE rpc */
	if (unlikely(lustre_msg_get_opc(req->rq_reqmsg) == OUT_UPDATE &&
		     CFS_FAIL_CHECK(OBD_FAIL_OUT_UPDATE_DROP)))
		RETURN(0);

	rc = tgt_request_preprocess(tsi, h, req);
	/* pack reply if reply format is fixed */
	if (rc == 0 && h->th_flags & HAS_REPLY) {
		/* Pack reply */
		if (req_capsule_has_field(tsi->tsi_pill, &RMF_MDT_MD,
					  RCL_SERVER))
			req_capsule_set_size(tsi->tsi_pill, &RMF_MDT_MD,
					     RCL_SERVER,
					     tsi->tsi_mdt_body->mbo_eadatasize);
		if (req_capsule_has_field(tsi->tsi_pill, &RMF_LOGCOOKIES,
					  RCL_SERVER))
			req_capsule_set_size(tsi->tsi_pill, &RMF_LOGCOOKIES,
					     RCL_SERVER, 0);
		if (req_capsule_has_field(tsi->tsi_pill, &RMF_ACL, RCL_SERVER))
			req_capsule_set_size(tsi->tsi_pill,
					     &RMF_ACL, RCL_SERVER,
					     LUSTRE_POSIX_ACL_MAX_SIZE_OLD);

		if (req_capsule_has_field(tsi->tsi_pill, &RMF_SHORT_IO,
					  RCL_SERVER)) {
			struct niobuf_remote *remote_nb =
				req_capsule_client_get(tsi->tsi_pill,
						       &RMF_NIOBUF_REMOTE);
			struct ost_body *body = tsi->tsi_ost_body;

			req_capsule_set_size(tsi->tsi_pill, &RMF_SHORT_IO,
					 RCL_SERVER,
					 (body->oa.o_valid & OBD_MD_FLFLAGS &&
					  body->oa.o_flags & OBD_FL_SHORT_IO) ?
					 remote_nb[0].rnb_len : 0);
		}
		if (req_capsule_has_field(tsi->tsi_pill, &RMF_FILE_ENCCTX,
					  RCL_SERVER))
			req_capsule_set_size(tsi->tsi_pill, &RMF_FILE_ENCCTX,
					     RCL_SERVER, 0);

		if (req_capsule_has_field(tsi->tsi_pill, &RMF_OBD_QUOTA_ITER,
					  RCL_SERVER)) {
			req_capsule_set_size(tsi->tsi_pill,
					    &RMF_OBD_QUOTA_ITER, RCL_SERVER, 0);
		}

		rc = req_capsule_server_pack(tsi->tsi_pill);
	}

	if (likely(rc == 0)) {
		/*
		 * Process request, there can be two types of rc:
		 * 1) errors with msg unpack/pack, other failures outside the
		 * operation itself. This is counted as serious errors;
		 * 2) errors during fs operation, should be placed in rq_status
		 * only
		 */
		rc = h->th_act(tsi);
		if (!is_serious(rc) &&
		    !req->rq_no_reply && req->rq_reply_state == NULL) {
			DEBUG_REQ(D_ERROR, req,
				  "%s: %s handler did not pack reply but returned no error",
				  tgt_name(tsi->tsi_tgt), h->th_name);
			LBUG();
		}
		serious = is_serious(rc);
		rc = clear_serious(rc);
	} else {
		serious = 1;
	}

	req->rq_status = rc;

	/*
	 * ELDLM_* codes which > 0 should be in rq_status only as well as
	 * all non-serious errors.
	 */
	if (rc > 0 || !serious)
		rc = 0;

	LASSERT(current->journal_info == NULL);

	if (likely(rc == 0 && req->rq_export))
		target_committed_to_req(req);

out:
	target_send_reply(req, rc, tsi->tsi_reply_fail_id);
	RETURN(0);
}

static int tgt_filter_recovery_request(struct ptlrpc_request *req,
				       struct obd_device *obd, int *process)
{
	switch (lustre_msg_get_opc(req->rq_reqmsg)) {
	case MDS_DISCONNECT:
	case OST_DISCONNECT:
	case OBD_IDX_READ:
		*process = 1;
		RETURN(0);
	case MDS_CLOSE:
	case MDS_SYNC: /* used in unmounting */
	case OBD_PING:
	case MDS_REINT:
	case OUT_UPDATE:
	case MDS_BATCH:
	case SEQ_QUERY:
	case FLD_QUERY:
	case FLD_READ:
	case LDLM_ENQUEUE:
	case OST_CREATE:
	case OST_DESTROY:
	case OST_PUNCH:
	case OST_SETATTR:
	case OST_SYNC:
	case OST_WRITE:
	case MDS_HSM_PROGRESS:
	case MDS_HSM_STATE_SET:
	case MDS_HSM_REQUEST:
	case MDS_HSM_DATA_VERSION:
	case OST_FALLOCATE:
		*process = target_queue_recovery_request(req, obd);
		RETURN(0);

	default:
		DEBUG_REQ(D_ERROR, req, "not permitted during recovery");
		*process = -EAGAIN;
		RETURN(0);
	}
}

/*
 * Handle recovery. Return:
 *        +1: continue request processing;
 *       -ve: abort immediately with the given error code;
 *         0: send reply with error code in req->rq_status;
 */
static int tgt_handle_recovery(struct ptlrpc_request *req, int reply_fail_id)
{
	ENTRY;

	switch (lustre_msg_get_opc(req->rq_reqmsg)) {
	case MDS_CONNECT:
	case OST_CONNECT:
	case MGS_CONNECT:
	case SEC_CTX_INIT:
	case SEC_CTX_INIT_CONT:
	case SEC_CTX_FINI:
		RETURN(+1);
	}

	if (!req->rq_export->exp_obd->obd_replayable)
		RETURN(+1);

	/* sanity check: if the xid matches, the request must be marked as a
	 * resent or replayed */
	if (req_can_reconstruct(req, NULL) == 1) {
		if (!(lustre_msg_get_flags(req->rq_reqmsg) &
		      (MSG_RESENT | MSG_REPLAY))) {
			DEBUG_REQ(D_WARNING, req,
				  "rq_xid=%llu matches saved XID, expected REPLAY or RESENT flag (%x)",
				  req->rq_xid,
				  lustre_msg_get_flags(req->rq_reqmsg));
			req->rq_status = -ENOTCONN;
			RETURN(-ENOTCONN);
		}
	}
	/* else: note the opposite is not always true; a RESENT req after a
	 * failover will usually not match the last_xid, since it was likely
	 * never committed. A REPLAYed request will almost never match the
	 * last xid, however it could for a committed, but still retained,
	 * open. */

	/* Check for aborted recovery... */
	if (unlikely(test_bit(OBDF_RECOVERING, req->rq_export->exp_obd->obd_flags))) {
		int rc;
		int should_process;

		DEBUG_REQ(D_INFO, req, "Got new replay");
		rc = tgt_filter_recovery_request(req, req->rq_export->exp_obd,
						 &should_process);
		if (rc != 0 || !should_process)
			RETURN(rc);
		else if (should_process < 0) {
			req->rq_status = should_process;
			rc = ptlrpc_error(req);
			RETURN(rc);
		}
	}
	RETURN(+1);
}

/* Initial check for request, it is validation mostly */
static struct tgt_handler *tgt_handler_find_check(struct ptlrpc_request *req)
{
	struct tgt_handler	*h;
	struct tgt_opc_slice	*s;
	struct lu_target	*tgt;
	__u32			 opc = lustre_msg_get_opc(req->rq_reqmsg);
	/* don't spew error messages for unhandled RPCs */
	static bool		 printed;

	ENTRY;

	tgt = class_exp2tgt(req->rq_export);
	if (unlikely(tgt == NULL)) {
		DEBUG_REQ(D_ERROR, req, "%s: no target for connected export",
			  class_exp2obd(req->rq_export)->obd_name);
		RETURN(ERR_PTR(-EINVAL));
	}

	for (s = tgt->lut_slice; s->tos_hs != NULL; s++)
		if (s->tos_opc_start <= opc && opc < s->tos_opc_end)
			break;

	/* opcode was not found in slice */
	if (unlikely(s->tos_hs == NULL)) {
		if (!printed) {
			CERROR("%s: no handler for opcode 0x%x from %s\n",
			       tgt_name(tgt), opc, libcfs_idstr(&req->rq_peer));
			printed = true;
		}
		goto err_unsupported;
	}

	LASSERT(opc >= s->tos_opc_start && opc < s->tos_opc_end);
	h = s->tos_hs + (opc - s->tos_opc_start);
	if (unlikely(h->th_opc == 0)) {
		if (!printed) {
			CERROR("%s: unsupported opcode 0x%x\n",
			       tgt_name(tgt), opc);
			printed = true;
		}
		goto err_unsupported;
	}

	if (CFS_FAIL_CHECK(OBD_FAIL_OST_OPCODE) && opc == cfs_fail_val)
		goto err_unsupported;

	RETURN(h);
err_unsupported:
	/*
	 * Unknown opcode does not necessarily means insane client. A new
	 * client might send RPCs with new opcodes to an old server. The
	 * client might desperately stuck there waiting for a reply. So,
	 * send an error back here.
	 *
	 * An old client might also send RPCs with deprecated opcodes (e.g.
	 * OST_QUOTACHECK).
	 *
	 * Error in ptlrpc_send_error() is ignored.
	 */
	req->rq_status = -EOPNOTSUPP;
	ptlrpc_send_error(req, PTLRPC_REPLY_MAYBE_DIFFICULT);
	RETURN(ERR_PTR(-EOPNOTSUPP));
}

static int process_req_last_xid(struct ptlrpc_request *req)
{
	__u64	last_xid;
	int rc = 0;
	struct obd_export *exp = req->rq_export;
	struct tg_export_data *ted = &exp->exp_target_data;
	bool need_lock = tgt_is_multimodrpcs_client(exp);
	ENTRY;

	if (need_lock)
		mutex_lock(&ted->ted_lcd_lock);
	/* check request's xid is consistent with export's last_xid */
	last_xid = lustre_msg_get_last_xid(req->rq_reqmsg);
	if (last_xid > exp->exp_last_xid)
		exp->exp_last_xid = last_xid;

	if (req->rq_xid == 0 || req->rq_xid <= exp->exp_last_xid) {
		/* Some request is allowed to be sent during replay,
		 * such as OUT update requests, FLD requests, so it
		 * is possible that replay requests has smaller XID
		 * than the exp_last_xid.
		 *
		 * Some non-replay requests may have smaller XID as
		 * well:
		 *
		 * - Client send a no_resend RPC, like statfs;
		 * - The RPC timedout (or some other error) on client,
		 *   then it's removed from the unreplied list;
		 * - Client send some other request to bump the
		 *   exp_last_xid on server;
		 * - The former RPC got chance to be processed;
		 */
		if (!(lustre_msg_get_flags(req->rq_reqmsg) & MSG_REPLAY))
			rc = -EPROTO;

		DEBUG_REQ(D_WARNING, req,
			  "unexpected xid=%llx != exp_last_xid=%llx, rc = %d",
			  req->rq_xid, exp->exp_last_xid, rc);
		if (rc)
			GOTO(out, rc);
	}

	/* The "last_xid" is the minimum xid among unreplied requests,
	 * if the request is from the previous connection, its xid can
	 * still be larger than "exp_last_xid", then the above check of
	 * xid is not enough to determine whether the request is delayed.
	 *
	 * For example, if some replay request was delayed and caused
	 * timeout at client and the replay is restarted, the delayed
	 * replay request will have the larger xid than "exp_last_xid"
	 */
	if (req->rq_export->exp_conn_cnt >
	    lustre_msg_get_conn_cnt(req->rq_reqmsg)) {
		CDEBUG(D_RPCTRACE,
		       "Dropping request %llu from an old epoch %u/%u\n",
		       req->rq_xid,
		       lustre_msg_get_conn_cnt(req->rq_reqmsg),
		       req->rq_export->exp_conn_cnt);
		req->rq_no_reply = 1;
		GOTO(out, rc = -ESTALE);
	}

	/* try to release in-memory reply data */
	if (tgt_is_multimodrpcs_client(exp)) {
		tgt_handle_received_xid(exp, last_xid);
		rc = tgt_handle_tag(req);
	}

out:
	if (need_lock)
		mutex_unlock(&ted->ted_lcd_lock);

	RETURN(rc);
}

int tgt_request_handle(struct ptlrpc_request *req)
{
	struct tgt_session_info	*tsi = tgt_ses_info(req->rq_svc_thread->t_env);

	struct lustre_msg	*msg = req->rq_reqmsg;
	struct tgt_handler	*h;
	struct lu_target	*tgt;
	int			 request_fail_id = 0;
	__u32			 opc = lustre_msg_get_opc(msg);
	struct obd_device	*obd;
	int			 rc;
	bool			 is_connect = false;
	ENTRY;

	if (unlikely(CFS_FAIL_CHECK(OBD_FAIL_TGT_RECOVERY_REQ_RACE))) {
		if (cfs_fail_val == 0 &&
		    lustre_msg_get_opc(msg) != OBD_PING &&
		    lustre_msg_get_flags(msg) & MSG_REQ_REPLAY_DONE) {
			cfs_fail_val = 1;
			cfs_race_state = 0;
			wait_event_idle(cfs_race_waitq, (cfs_race_state == 1));
		}
	}

	req_capsule_init(&req->rq_pill, req, RCL_SERVER);
	tsi->tsi_pill = &req->rq_pill;
	tsi->tsi_env = req->rq_svc_thread->t_env;

	/* if request has export then get handlers slice from corresponding
	 * target, otherwise that should be connect operation */
	if (opc == MDS_CONNECT || opc == OST_CONNECT ||
	    opc == MGS_CONNECT) {
		is_connect = true;
		req_capsule_set(&req->rq_pill, &RQF_CONNECT);
		rc = target_handle_connect(req);
		if (rc != 0) {
			rc = ptlrpc_error(req);
			GOTO(out, rc);
		}
		/* recovery-small test 18c asks to drop connect reply */
		if (unlikely(opc == OST_CONNECT &&
			     CFS_FAIL_CHECK(OBD_FAIL_OST_CONNECT_NET2)))
			GOTO(out, rc = 0);
	}

	if (unlikely(!class_connected_export(req->rq_export))) {
		if (opc == SEC_CTX_INIT || opc == SEC_CTX_INIT_CONT ||
		    opc == SEC_CTX_FINI) {
			/* sec context initialization has to be handled
			 * by hand in tgt_handle_request0() */
			tsi->tsi_reply_fail_id = OBD_FAIL_SEC_CTX_INIT_NET;
			h = NULL;
			GOTO(handle_recov, rc = 0);
		}
		CDEBUG(D_HA, "operation %d on unconnected OST from %s\n",
		       opc, libcfs_idstr(&req->rq_peer));
		req->rq_status = -ENOTCONN;
		rc = ptlrpc_error(req);
		GOTO(out, rc);
	}

	tsi->tsi_tgt = tgt = class_exp2tgt(req->rq_export);
	tsi->tsi_exp = req->rq_export;
	if (exp_connect_flags(req->rq_export) & OBD_CONNECT_JOBSTATS)
		tsi->tsi_jobid = lustre_msg_get_jobid(req->rq_reqmsg);
	else
		tsi->tsi_jobid = NULL;

	if (tgt == NULL) {
		DEBUG_REQ(D_ERROR, req, "%s: No target for connected export",
			  class_exp2obd(req->rq_export)->obd_name);
		req->rq_status = -EINVAL;
		rc = ptlrpc_error(req);
		GOTO(out, rc);
	}

	/* Skip last_xid processing for the recovery thread, otherwise, the
	 * last_xid on same request could be processed twice: first time when
	 * processing the incoming request, second time when the request is
	 * being processed by recovery thread. */
	obd = class_exp2obd(req->rq_export);
	if (is_connect) {
		/* reset the exp_last_xid on each connection. */
		req->rq_export->exp_last_xid = 0;
	} else if (obd->obd_recovery_data.trd_processing_task !=
		   current->pid) {
		rc = process_req_last_xid(req);
		if (rc) {
			req->rq_status = rc;
			rc = ptlrpc_error(req);
			GOTO(out, rc);
		}
	}

	request_fail_id = tgt->lut_request_fail_id;
	tsi->tsi_reply_fail_id = tgt->lut_reply_fail_id;

	h = tgt_handler_find_check(req);
	if (IS_ERR(h)) {
		req->rq_status = PTR_ERR(h);
		rc = ptlrpc_error(req);
		GOTO(out, rc);
	}

	LASSERTF(h->th_opc == opc, "opcode mismatch %d != %d\n",
		 h->th_opc, opc);

	if ((cfs_fail_val == 0 || cfs_fail_val == opc) &&
	     CFS_FAIL_CHECK_ORSET(request_fail_id, CFS_FAIL_ONCE))
		GOTO(out, rc = 0);

	rc = lustre_msg_check_version(msg, h->th_version);
	if (unlikely(rc)) {
		DEBUG_REQ(D_ERROR, req,
			  "%s: drop malformed request version=%08x expect=%08x",
			  tgt_name(tgt), lustre_msg_get_version(msg),
			  h->th_version);
		req->rq_status = -EINVAL;
		rc = ptlrpc_error(req);
		GOTO(out, rc);
	}

handle_recov:
	rc = tgt_handle_recovery(req, tsi->tsi_reply_fail_id);
	if (likely(rc == 1)) {
		rc = tgt_handle_request0(tsi, h, req);
		if (rc)
			GOTO(out, rc);
	}
	EXIT;
out:
	req_capsule_fini(tsi->tsi_pill);
	if (tsi->tsi_corpus != NULL) {
		lu_object_put(tsi->tsi_env, tsi->tsi_corpus);
		tsi->tsi_corpus = NULL;
	}
	return rc;
}
EXPORT_SYMBOL(tgt_request_handle);

/** Assign high priority operations to the request if needed. */
int tgt_hpreq_handler(struct ptlrpc_request *req)
{
	struct tgt_session_info	*tsi = tgt_ses_info(req->rq_svc_thread->t_env);
	struct tgt_handler	*h;
	int			 rc;

	ENTRY;

	if (req->rq_export == NULL)
		RETURN(0);

	req_capsule_init(&req->rq_pill, req, RCL_SERVER);
	tsi->tsi_pill = &req->rq_pill;
	tsi->tsi_env = req->rq_svc_thread->t_env;
	tsi->tsi_tgt = class_exp2tgt(req->rq_export);
	tsi->tsi_exp = req->rq_export;

	h = tgt_handler_find_check(req);
	if (IS_ERR(h)) {
		rc = PTR_ERR(h);
		RETURN(rc);
	}

	rc = tgt_request_preprocess(tsi, h, req);
	if (unlikely(rc != 0))
		RETURN(rc);

	if (h->th_hp != NULL)
		h->th_hp(tsi);
	RETURN(0);
}
EXPORT_SYMBOL(tgt_hpreq_handler);

void tgt_counter_incr(struct obd_export *exp, int opcode)
{
	lprocfs_counter_incr(exp->exp_obd->obd_stats, opcode);
	if (exp->exp_nid_stats && exp->exp_nid_stats->nid_stats != NULL)
		lprocfs_counter_incr(exp->exp_nid_stats->nid_stats, opcode);
}
EXPORT_SYMBOL(tgt_counter_incr);

/*
 * Unified target generic handlers.
 */

int tgt_connect_check_sptlrpc(struct ptlrpc_request *req, struct obd_export *exp)
{
	struct lu_target *tgt = class_exp2tgt(exp);
	struct sptlrpc_flavor flvr;
	int rc = 0;

	LASSERT(tgt);
	LASSERT(tgt->lut_obd);
	LASSERT(tgt->lut_slice);

	/* always allow ECHO client */
	if (unlikely(strcmp(exp->exp_obd->obd_type->typ_name,
			    LUSTRE_ECHO_NAME) == 0)) {
		exp->exp_flvr.sf_rpc = SPTLRPC_FLVR_ANY;
		return 0;
	}

	if (exp->exp_flvr.sf_rpc == SPTLRPC_FLVR_INVALID) {
		read_lock(&tgt->lut_sptlrpc_lock);
		sptlrpc_target_choose_flavor(&tgt->lut_sptlrpc_rset,
					     req->rq_sp_from,
					     &req->rq_peer.nid,
					     &flvr);
		read_unlock(&tgt->lut_sptlrpc_lock);

		spin_lock(&exp->exp_lock);
		exp->exp_sp_peer = req->rq_sp_from;
		exp->exp_flvr = flvr;

		/* when on mgs, if no restriction is set, or if the client
		 * NID is on the local node, allow any flavor
		 */
		if ((strcmp(exp->exp_obd->obd_type->typ_name,
			    LUSTRE_MGS_NAME) == 0) &&
		    (exp->exp_flvr.sf_rpc == SPTLRPC_FLVR_NULL ||
		     LNetIsPeerLocal(&exp->exp_connection->c_peer.nid)))
			exp->exp_flvr.sf_rpc = SPTLRPC_FLVR_ANY;

		if (exp->exp_flvr.sf_rpc != SPTLRPC_FLVR_ANY &&
		    exp->exp_flvr.sf_rpc != req->rq_flvr.sf_rpc) {
			CERROR("%s: unauthorized rpc flavor %x from %s, "
			       "expect %x\n", tgt_name(tgt),
			       req->rq_flvr.sf_rpc,
			       libcfs_nidstr(&req->rq_peer.nid),
			       exp->exp_flvr.sf_rpc);
			rc = -EACCES;
		}
		spin_unlock(&exp->exp_lock);
	} else {
		if (exp->exp_sp_peer != req->rq_sp_from) {
			CERROR("%s: RPC source %s doesn't match %s\n",
			       tgt_name(tgt),
			       sptlrpc_part2name(req->rq_sp_from),
			       sptlrpc_part2name(exp->exp_sp_peer));
			rc = -EACCES;
		} else {
			rc = sptlrpc_target_export_check(exp, req);
		}
	}

	return rc;
}

int tgt_adapt_sptlrpc_conf(struct lu_target *tgt)
{
	struct sptlrpc_rule_set	 tmp_rset;
	int			 rc;

	if (unlikely(tgt == NULL)) {
		CERROR("No target passed\n");
		return -EINVAL;
	}

	sptlrpc_rule_set_init(&tmp_rset);
	rc = sptlrpc_conf_target_get_rules(tgt->lut_obd, &tmp_rset);
	if (rc) {
		CERROR("%s: failed get sptlrpc rules: rc = %d\n",
		       tgt_name(tgt), rc);
		return rc;
	}

	sptlrpc_target_update_exp_flavor(tgt->lut_obd, &tmp_rset);

	write_lock(&tgt->lut_sptlrpc_lock);
	sptlrpc_rule_set_free(&tgt->lut_sptlrpc_rset);
	tgt->lut_sptlrpc_rset = tmp_rset;
	write_unlock(&tgt->lut_sptlrpc_lock);

	return 0;
}
EXPORT_SYMBOL(tgt_adapt_sptlrpc_conf);

int tgt_connect(struct tgt_session_info *tsi)
{
	struct ptlrpc_request	*req = tgt_ses_req(tsi);
	struct obd_connect_data	*reply;
	int			 rc;

	ENTRY;

	/* XXX: better to call this check right after getting new export but
	 * before last_rcvd slot allocation to avoid server load upon insecure
	 * connects. This is to be fixed after unifiyng all targets.
	 */
	rc = tgt_connect_check_sptlrpc(req, tsi->tsi_exp);
	if (rc)
		GOTO(out, rc);

	/* To avoid exposing partially initialized connection flags, changes up
	 * to this point have been staged in reply->ocd_connect_flags. Now that
	 * connection handling has completed successfully, atomically update
	 * the connect flags in the shared export data structure. LU-1623 */
	reply = req_capsule_server_get(tsi->tsi_pill, &RMF_CONNECT_DATA);
	spin_lock(&tsi->tsi_exp->exp_lock);
	*exp_connect_flags_ptr(tsi->tsi_exp) = reply->ocd_connect_flags;
	if (reply->ocd_connect_flags & OBD_CONNECT_FLAGS2)
		*exp_connect_flags2_ptr(tsi->tsi_exp) =
			reply->ocd_connect_flags2;
	tsi->tsi_exp->exp_connect_data.ocd_brw_size = reply->ocd_brw_size;
	spin_unlock(&tsi->tsi_exp->exp_lock);

	if (strcmp(tsi->tsi_exp->exp_obd->obd_type->typ_name,
		   LUSTRE_MDT_NAME) == 0) {
		struct lu_nodemap *nm = NULL;

		if (CFS_FAIL_CHECK(OBD_FAIL_MDS_CONNECT_ACCESS))
			GOTO(out, rc = -EACCES);

		rc = req_check_sepol(tsi->tsi_pill);
		if (rc)
			GOTO(out, rc);

		if (tsi->tsi_pill->rc_req->rq_export)
			nm =
			 nodemap_get_from_exp(tsi->tsi_pill->rc_req->rq_export);

		if (reply->ocd_connect_flags & OBD_CONNECT_FLAGS2 &&
		    reply->ocd_connect_flags2 & OBD_CONNECT2_ENCRYPT) {
			bool forbid_encrypt = true;

			if (!nm)
				/* nodemap_get_from_exp returns NULL in case
				 * nodemap is not active, so we do not forbid
				 */
				forbid_encrypt = false;
			else if (!IS_ERR(nm))
				forbid_encrypt = nm->nmf_forbid_encryption;
			if (forbid_encrypt)
				GOTO(put_nm, rc = -EACCES);
		}

		if (!(reply->ocd_connect_flags & OBD_CONNECT_RDONLY)) {
			bool readonly = false;

			if (!IS_ERR_OR_NULL(nm))
				readonly = nm->nmf_readonly_mount;
			if (unlikely(readonly))
				GOTO(put_nm, rc = -EROFS);
		}

put_nm:
		if (!IS_ERR_OR_NULL(nm))
			nodemap_putref(nm);
		if (rc)
			GOTO(out, rc);
	}

	RETURN(0);
out:
	obd_disconnect(class_export_get(tsi->tsi_exp));
	return rc;
}
EXPORT_SYMBOL(tgt_connect);

int tgt_disconnect(struct tgt_session_info *tsi)
{
	int rc;

	ENTRY;

	CFS_FAIL_TIMEOUT(OBD_FAIL_OST_DISCONNECT_DELAY, cfs_fail_val);

	rc = target_handle_disconnect(tgt_ses_req(tsi));
	if (rc)
		RETURN(err_serious(rc));

	RETURN(rc);
}
EXPORT_SYMBOL(tgt_disconnect);

/*
 * Unified target OBD handlers
 */
int tgt_obd_ping(struct tgt_session_info *tsi)
{
	int rc;

	ENTRY;

	/* The target-specific part of OBD_PING request handling.
	 * It controls Filter Modification Data (FMD) expiration each time
	 * PING is received.
	 *
	 * Valid only for replayable targets, e.g. MDT and OFD
	 */
	if (tsi->tsi_exp->exp_obd->obd_replayable)
		tgt_fmd_expire(tsi->tsi_exp);

	rc = req_capsule_server_pack(tsi->tsi_pill);
	if (rc)
		RETURN(err_serious(rc));

	if (CFS_FAIL_CHECK(OBD_FAIL_MDS_CONNECT_VS_EVICT)) {
		if (strstr(tsi->tsi_exp->exp_obd->obd_name, "MDT0000") &&
		    (exp_connect_flags(tsi->tsi_exp) & OBD_CONNECT_MDS_MDS))
			tsi->tsi_pill->rc_req->rq_no_reply = 1;
	}

	RETURN(rc);
}
EXPORT_SYMBOL(tgt_obd_ping);

int tgt_send_buffer(struct tgt_session_info *tsi, struct lu_rdbuf *rdbuf)
{
	struct ptlrpc_request	*req = tgt_ses_req(tsi);
	struct obd_export	*exp = req->rq_export;
	struct ptlrpc_bulk_desc	*desc;
	int			 i;
	int			 rc;
	int			 pages = 0;

	ENTRY;

	for (i = 0; i < rdbuf->rb_nbufs; i++) {
		unsigned int offset;

		offset = (unsigned long)rdbuf->rb_bufs[i].lb_buf & ~PAGE_MASK;
		pages += DIV_ROUND_UP(rdbuf->rb_bufs[i].lb_len + offset,
				      PAGE_SIZE);
	}

	desc = ptlrpc_prep_bulk_exp(req, pages, 1,
				  PTLRPC_BULK_PUT_SOURCE,
				    MDS_BULK_PORTAL,
				    &ptlrpc_bulk_kiov_nopin_ops);
	if (desc == NULL)
		RETURN(-ENOMEM);

	for (i = 0; i < rdbuf->rb_nbufs; i++)
		desc->bd_frag_ops->add_iov_frag(desc,
					rdbuf->rb_bufs[i].lb_buf,
					rdbuf->rb_bufs[i].lb_len);

	rc = target_bulk_io(exp, desc);
	ptlrpc_free_bulk(desc);
	RETURN(rc);
}
EXPORT_SYMBOL(tgt_send_buffer);

int tgt_sendpage(struct tgt_session_info *tsi, struct lu_rdpg *rdpg, int nob)
{
	struct ptlrpc_request	*req = tgt_ses_req(tsi);
	struct obd_export	*exp = req->rq_export;
	struct ptlrpc_bulk_desc	*desc;
	int			 tmpcount;
	int			 tmpsize;
	int			 i;
	int			 rc;

	ENTRY;

	desc = ptlrpc_prep_bulk_exp(req, rdpg->rp_npages, 1,
				    PTLRPC_BULK_PUT_SOURCE,
				    MDS_BULK_PORTAL,
				    &ptlrpc_bulk_kiov_pin_ops);
	if (desc == NULL)
		RETURN(-ENOMEM);

	if (!(exp_connect_flags(exp) & OBD_CONNECT_BRW_SIZE))
		/* old client requires reply size in it's PAGE_SIZE,
		 * which is rdpg->rp_count */
		nob = rdpg->rp_count;

	for (i = 0, tmpcount = nob; i < rdpg->rp_npages && tmpcount > 0;
	     i++, tmpcount -= tmpsize) {
		tmpsize = min_t(int, tmpcount, PAGE_SIZE);
		desc->bd_frag_ops->add_kiov_frag(desc, rdpg->rp_pages[i], 0,
						 tmpsize);
	}

	LASSERT(desc->bd_nob == nob);
	rc = target_bulk_io(exp, desc);
	ptlrpc_free_bulk(desc);
	RETURN(rc);
}
EXPORT_SYMBOL(tgt_sendpage);

/*
 * OBD_IDX_READ handler
 */
static int tgt_obd_idx_read(struct tgt_session_info *tsi)
{
	struct tgt_thread_info	*tti = tgt_th_info(tsi->tsi_env);
	struct lu_rdpg		*rdpg = &tti->tti_u.rdpg.tti_rdpg;
	struct idx_info		*req_ii, *rep_ii;
	int			 rc, i;

	ENTRY;

	memset(rdpg, 0, sizeof(*rdpg));
	req_capsule_set(tsi->tsi_pill, &RQF_OBD_IDX_READ);

	/* extract idx_info buffer from request & reply */
	req_ii = req_capsule_client_get(tsi->tsi_pill, &RMF_IDX_INFO);
	if (req_ii == NULL || req_ii->ii_magic != IDX_INFO_MAGIC)
		RETURN(err_serious(-EPROTO));

	rc = req_capsule_server_pack(tsi->tsi_pill);
	if (rc)
		RETURN(err_serious(rc));

	rep_ii = req_capsule_server_get(tsi->tsi_pill, &RMF_IDX_INFO);
	if (rep_ii == NULL)
		RETURN(err_serious(-EFAULT));
	rep_ii->ii_magic = IDX_INFO_MAGIC;

	/* extract hash to start with */
	rdpg->rp_hash = req_ii->ii_hash_start;

	/* extract requested attributes */
	rdpg->rp_attrs = req_ii->ii_attrs;

	/* check that fid packed in request is valid and supported */
	if (!fid_is_sane(&req_ii->ii_fid))
		RETURN(-EINVAL);
	rep_ii->ii_fid = req_ii->ii_fid;

	/* copy flags */
	rep_ii->ii_flags = req_ii->ii_flags;

	/* compute number of pages to allocate, ii_count is the number of 4KB
	 * containers */
	if (req_ii->ii_count <= 0)
		GOTO(out, rc = -EFAULT);
	rdpg->rp_count = min_t(unsigned int, req_ii->ii_count << LU_PAGE_SHIFT,
			       exp_max_brw_size(tsi->tsi_exp));
	rdpg->rp_npages = (rdpg->rp_count + PAGE_SIZE - 1) >> PAGE_SHIFT;

	/* allocate pages to store the containers */
	OBD_ALLOC_PTR_ARRAY(rdpg->rp_pages, rdpg->rp_npages);
	if (rdpg->rp_pages == NULL)
		GOTO(out, rc = -ENOMEM);
	for (i = 0; i < rdpg->rp_npages; i++) {
		rdpg->rp_pages[i] = alloc_page(GFP_NOFS);
		if (rdpg->rp_pages[i] == NULL)
			GOTO(out, rc = -ENOMEM);
	}

	/* populate pages with key/record pairs */
	rc = dt_index_read(tsi->tsi_env, tsi->tsi_tgt->lut_bottom, rep_ii, rdpg);
	if (rc < 0)
		GOTO(out, rc);

	LASSERTF(rc <= rdpg->rp_count, "dt_index_read() returned more than "
		 "asked %d > %d\n", rc, rdpg->rp_count);

	/* send pages to client */
	rc = tgt_sendpage(tsi, rdpg, rc);
	if (rc)
		GOTO(out, rc);
	EXIT;
out:
	if (rdpg->rp_pages) {
		for (i = 0; i < rdpg->rp_npages; i++)
			if (rdpg->rp_pages[i])
				__free_page(rdpg->rp_pages[i]);
		OBD_FREE_PTR_ARRAY(rdpg->rp_pages, rdpg->rp_npages);
	}
	return rc;
}

struct tgt_handler tgt_obd_handlers[] = {
TGT_OBD_HDL    (0,	OBD_PING,		tgt_obd_ping),
TGT_OBD_HDL    (0,	OBD_IDX_READ,		tgt_obd_idx_read)
};
EXPORT_SYMBOL(tgt_obd_handlers);

int tgt_sync(const struct lu_env *env, struct lu_target *tgt,
	     struct dt_object *obj, __u64 start, __u64 end)
{
	int rc = 0;

	ENTRY;

	/* if no objid is specified, it means "sync whole filesystem" */
	if (obj == NULL) {
		rc = dt_sync(env, tgt->lut_bottom);
	} else if (dt_version_get(env, obj) >
		   tgt->lut_obd->obd_last_committed) {
		rc = dt_object_sync(env, obj, start, end);
	}
	atomic_inc(&tgt->lut_sync_count);

	RETURN(rc);
}
EXPORT_SYMBOL(tgt_sync);
/*
 * Unified target DLM handlers.
 */

/**
 * Unified target BAST
 *
 * Ensure data and metadata are synced to disk when lock is canceled if Sync on
 * Cancel (SOC) is enabled. If it's extent lock, normally sync obj is enough,
 * but if it's cross-MDT lock, because remote object version is not set, a
 * filesystem sync is needed.
 *
 * \param lock server side lock
 * \param desc lock desc
 * \param data ldlm_cb_set_arg
 * \param flag	indicates whether this cancelling or blocking callback
 * \retval	0 on success
 * \retval	negative number on error
 */
int tgt_blocking_ast(struct ldlm_lock *lock, struct ldlm_lock_desc *desc,
		     void *data, int flag)
{
	struct lu_env		 env;
	struct lu_target	*tgt;
	struct dt_object	*obj = NULL;
	struct lu_fid		 fid;
	int			 rc = 0;

	ENTRY;

	tgt = class_exp2tgt(lock->l_export);

	if (unlikely(tgt == NULL)) {
		CDEBUG(D_ERROR, "%s: No target for connected export\n",
		       class_exp2obd(lock->l_export)->obd_name);
		RETURN(-EINVAL);
	}

	if (flag == LDLM_CB_CANCELING &&
	    (lock->l_granted_mode & (LCK_EX | LCK_PW | LCK_GROUP)) &&
	    (tgt->lut_sync_lock_cancel == SYNC_LOCK_CANCEL_ALWAYS ||
	     (tgt->lut_sync_lock_cancel == SYNC_LOCK_CANCEL_BLOCKING &&
	      (lock->l_flags & LDLM_FL_CBPENDING))) &&
	    ((exp_connect_flags(lock->l_export) & OBD_CONNECT_MDS_MDS) ||
	     lock->l_resource->lr_type == LDLM_EXTENT)) {
		__u64 start = 0;
		__u64 end = OBD_OBJECT_EOF;

		rc = lu_env_init(&env, LCT_DT_THREAD);
		if (unlikely(rc != 0))
			GOTO(err, rc);

		ost_fid_from_resid(&fid, &lock->l_resource->lr_name,
				   tgt->lut_lsd.lsd_osd_index);

		if (lock->l_resource->lr_type == LDLM_EXTENT) {
			obj = dt_locate(&env, tgt->lut_bottom, &fid);
			if (IS_ERR(obj))
				GOTO(err_env, rc = PTR_ERR(obj));

			if (!dt_object_exists(obj))
				GOTO(err_put, rc = -ENOENT);

			start = lock->l_policy_data.l_extent.start;
			end = lock->l_policy_data.l_extent.end;
		}

		rc = tgt_sync(&env, tgt, obj, start, end);
		if (rc < 0) {
			CERROR("%s: syncing "DFID" (%llu-%llu) on lock "
			       "cancel: rc = %d\n",
			       tgt_name(tgt), PFID(&fid),
			       lock->l_policy_data.l_extent.start,
			       lock->l_policy_data.l_extent.end, rc);
		}
err_put:
		if (obj != NULL)
			dt_object_put(&env, obj);
err_env:
		lu_env_fini(&env);
	}
err:
	rc = ldlm_server_blocking_ast(lock, desc, data, flag);
	RETURN(rc);
}
EXPORT_SYMBOL(tgt_blocking_ast);

static struct ldlm_callback_suite tgt_dlm_cbs = {
	.lcs_completion	= ldlm_server_completion_ast,
	.lcs_blocking	= tgt_blocking_ast,
	.lcs_glimpse	= ldlm_server_glimpse_ast
};

int tgt_enqueue(struct tgt_session_info *tsi)
{
	struct ptlrpc_request *req = tgt_ses_req(tsi);
	int rc;

	ENTRY;
	/*
	 * tsi->tsi_dlm_req was already swapped and (if necessary) converted,
	 * tsi->tsi_dlm_cbs was set by the *_req_handle() function.
	 */
	LASSERT(tsi->tsi_dlm_req != NULL);
	rc = ldlm_handle_enqueue(tsi->tsi_exp->exp_obd->obd_namespace,
				 &req->rq_pill, tsi->tsi_dlm_req, &tgt_dlm_cbs);
	if (rc)
		RETURN(err_serious(rc));

	switch (LUT_FAIL_CLASS(tsi->tsi_reply_fail_id)) {
	case LUT_FAIL_MDT:
		tsi->tsi_reply_fail_id = OBD_FAIL_MDS_LDLM_REPLY_NET;
		break;
	case LUT_FAIL_OST:
		tsi->tsi_reply_fail_id = OBD_FAIL_OST_LDLM_REPLY_NET;
		break;
	case LUT_FAIL_MGT:
		tsi->tsi_reply_fail_id = OBD_FAIL_MGS_LDLM_REPLY_NET;
		break;
	default:
		tsi->tsi_reply_fail_id = OBD_FAIL_LDLM_REPLY;
		break;
	}
	RETURN(req->rq_status);
}
EXPORT_SYMBOL(tgt_enqueue);

int tgt_convert(struct tgt_session_info *tsi)
{
	struct ptlrpc_request *req = tgt_ses_req(tsi);
	int rc;

	ENTRY;
	LASSERT(tsi->tsi_dlm_req);
	rc = ldlm_handle_convert0(req, tsi->tsi_dlm_req);
	if (rc)
		RETURN(err_serious(rc));

	RETURN(req->rq_status);
}

int tgt_bl_callback(struct tgt_session_info *tsi)
{
	return err_serious(-EOPNOTSUPP);
}

int tgt_cp_callback(struct tgt_session_info *tsi)
{
	return err_serious(-EOPNOTSUPP);
}

/* generic LDLM target handler */
struct tgt_handler tgt_dlm_handlers[] = {
TGT_DLM_HDL(HAS_KEY, LDLM_ENQUEUE, tgt_enqueue),
TGT_DLM_HDL(HAS_KEY, LDLM_CONVERT, tgt_convert),
TGT_DLM_HDL_VAR(0, LDLM_BL_CALLBACK, tgt_bl_callback),
TGT_DLM_HDL_VAR(0, LDLM_CP_CALLBACK, tgt_cp_callback)
};
EXPORT_SYMBOL(tgt_dlm_handlers);

/*
 * Unified target LLOG handlers.
 */
int tgt_llog_open(struct tgt_session_info *tsi)
{
	int rc;

	ENTRY;

	rc = llog_origin_handle_open(tgt_ses_req(tsi));

	RETURN(rc);
}
EXPORT_SYMBOL(tgt_llog_open);

int tgt_llog_read_header(struct tgt_session_info *tsi)
{
	int rc;

	ENTRY;

	rc = llog_origin_handle_read_header(tgt_ses_req(tsi));

	RETURN(rc);
}
EXPORT_SYMBOL(tgt_llog_read_header);

int tgt_llog_next_block(struct tgt_session_info *tsi)
{
	int rc;

	ENTRY;

	rc = llog_origin_handle_next_block(tgt_ses_req(tsi));

	RETURN(rc);
}
EXPORT_SYMBOL(tgt_llog_next_block);

int tgt_llog_prev_block(struct tgt_session_info *tsi)
{
	int rc;

	ENTRY;

	rc = llog_origin_handle_prev_block(tgt_ses_req(tsi));

	RETURN(rc);
}
EXPORT_SYMBOL(tgt_llog_prev_block);

/* generic llog target handler */
struct tgt_handler tgt_llog_handlers[] = {
TGT_LLOG_HDL    (0,	LLOG_ORIGIN_HANDLE_CREATE,	tgt_llog_open),
TGT_LLOG_HDL    (0,	LLOG_ORIGIN_HANDLE_NEXT_BLOCK,	tgt_llog_next_block),
TGT_LLOG_HDL    (0,	LLOG_ORIGIN_HANDLE_READ_HEADER,	tgt_llog_read_header),
TGT_LLOG_HDL    (0,	LLOG_ORIGIN_HANDLE_PREV_BLOCK,	tgt_llog_prev_block),
};
EXPORT_SYMBOL(tgt_llog_handlers);

/*
 * sec context handlers
 */
/* XXX: Implement based on mdt_sec_ctx_handle()? */
static int tgt_sec_ctx_handle(struct tgt_session_info *tsi)
{
	return 0;
}

struct tgt_handler tgt_sec_ctx_handlers[] = {
TGT_SEC_HDL_VAR(0,	SEC_CTX_INIT,		tgt_sec_ctx_handle),
TGT_SEC_HDL_VAR(0,	SEC_CTX_INIT_CONT,	tgt_sec_ctx_handle),
TGT_SEC_HDL_VAR(0,	SEC_CTX_FINI,		tgt_sec_ctx_handle),
};
EXPORT_SYMBOL(tgt_sec_ctx_handlers);

int (*tgt_lfsck_in_notify_local)(const struct lu_env *env,
				 struct dt_device *key,
				 struct lfsck_req_local *lrl,
				 struct thandle *th) = NULL;

void tgt_register_lfsck_in_notify_local(int (*notify)(const struct lu_env *,
						      struct dt_device *,
						      struct lfsck_req_local *,
						      struct thandle *))
{
	tgt_lfsck_in_notify_local = notify;
}
EXPORT_SYMBOL(tgt_register_lfsck_in_notify_local);

static int (*tgt_lfsck_in_notify)(const struct lu_env *env,
				  struct dt_device *key,
				  struct lfsck_request *lr) = NULL;

void tgt_register_lfsck_in_notify(int (*notify)(const struct lu_env *,
						struct dt_device *,
						struct lfsck_request *))
{
	tgt_lfsck_in_notify = notify;
}
EXPORT_SYMBOL(tgt_register_lfsck_in_notify);

static int (*tgt_lfsck_query)(const struct lu_env *env,
			      struct dt_device *key,
			      struct lfsck_request *req,
			      struct lfsck_reply *rep,
			      struct lfsck_query *que) = NULL;

void tgt_register_lfsck_query(int (*query)(const struct lu_env *,
					   struct dt_device *,
					   struct lfsck_request *,
					   struct lfsck_reply *,
					   struct lfsck_query *))
{
	tgt_lfsck_query = query;
}
EXPORT_SYMBOL(tgt_register_lfsck_query);

/* LFSCK request handlers */
static int tgt_handle_lfsck_notify(struct tgt_session_info *tsi)
{
	const struct lu_env	*env = tsi->tsi_env;
	struct dt_device	*key = tsi->tsi_tgt->lut_bottom;
	struct lfsck_request	*lr;
	int			 rc;
	ENTRY;

	lr = req_capsule_client_get(tsi->tsi_pill, &RMF_LFSCK_REQUEST);
	if (lr == NULL)
		RETURN(-EPROTO);

	rc = tgt_lfsck_in_notify(env, key, lr);

	RETURN(rc);
}

static int tgt_handle_lfsck_query(struct tgt_session_info *tsi)
{
	struct lfsck_request	*request;
	struct lfsck_reply	*reply;
	int			 rc;
	ENTRY;

	request = req_capsule_client_get(tsi->tsi_pill, &RMF_LFSCK_REQUEST);
	if (request == NULL)
		RETURN(-EPROTO);

	reply = req_capsule_server_get(tsi->tsi_pill, &RMF_LFSCK_REPLY);
	if (reply == NULL)
		RETURN(-ENOMEM);

	rc = tgt_lfsck_query(tsi->tsi_env, tsi->tsi_tgt->lut_bottom,
			     request, reply, NULL);

	RETURN(rc < 0 ? rc : 0);
}

struct tgt_handler tgt_lfsck_handlers[] = {
TGT_LFSCK_HDL(HAS_REPLY,	LFSCK_NOTIFY,	tgt_handle_lfsck_notify),
TGT_LFSCK_HDL(HAS_REPLY,	LFSCK_QUERY,	tgt_handle_lfsck_query),
};
EXPORT_SYMBOL(tgt_lfsck_handlers);

/*
 * initialize per-thread page pool (bug 5137).
 */
int tgt_io_thread_init(struct ptlrpc_thread *thread)
{
	struct tgt_thread_big_cache *tbc;

	ENTRY;

	LASSERT(thread != NULL);
	LASSERT(thread->t_data == NULL);

	OBD_ALLOC_LARGE(tbc, sizeof(*tbc));
	if (tbc == NULL)
		RETURN(-ENOMEM);
	thread->t_data = tbc;
	RETURN(0);
}
EXPORT_SYMBOL(tgt_io_thread_init);

/*
 * free per-thread pool created by tgt_thread_init().
 */
void tgt_io_thread_done(struct ptlrpc_thread *thread)
{
	struct tgt_thread_big_cache *tbc;

	ENTRY;

	LASSERT(thread != NULL);

	/*
	 * be prepared to handle partially-initialized pools (because this is
	 * called from ost_io_thread_init() for cleanup.
	 */
	tbc = thread->t_data;
	if (tbc != NULL) {
		OBD_FREE_LARGE(tbc, sizeof(*tbc));
		thread->t_data = NULL;
	}
	EXIT;
}
EXPORT_SYMBOL(tgt_io_thread_done);

/**
 * Helper function for getting Data-on-MDT file server DLM lock
 * if asked by client.
 */
int tgt_mdt_data_lock(struct ldlm_namespace *ns, struct ldlm_res_id *res_id,
		      struct lustre_handle *lh, int mode, __u64 *flags)
{
	union ldlm_policy_data policy = {
		.l_inodebits.bits = MDS_INODELOCK_DOM,
	};
	int rc;

	ENTRY;

	LASSERT(lh != NULL);
	LASSERT(ns != NULL);
	LASSERT(!lustre_handle_is_used(lh));

	rc = ldlm_cli_enqueue_local(NULL, ns, res_id, LDLM_IBITS, &policy, mode,
				    flags, ldlm_blocking_ast,
				    ldlm_completion_ast, ldlm_glimpse_ast,
				    NULL, 0, LVB_T_NONE, NULL, lh);

	RETURN(rc == ELDLM_OK ? 0 : -EIO);
}
EXPORT_SYMBOL(tgt_mdt_data_lock);

/**
 * Helper function for getting server side [start, start+count] DLM lock
 * if asked by client.
 */
int tgt_extent_lock(const struct lu_env *env, struct ldlm_namespace *ns,
		    struct ldlm_res_id *res_id, __u64 start, __u64 end,
		    struct lustre_handle *lh, int mode, __u64 *flags)
{
	union ldlm_policy_data policy;
	int rc;

	ENTRY;

	LASSERT(lh != NULL);
	LASSERT(ns != NULL);
	LASSERT(!lustre_handle_is_used(lh));

	policy.l_extent.gid = 0;
	policy.l_extent.start = start & PAGE_MASK;

	/*
	 * If ->o_blocks is EOF it means "lock till the end of the file".
	 * Otherwise, it's size of an extent or hole being punched (in bytes).
	 */
	if (end == OBD_OBJECT_EOF || end < start)
		policy.l_extent.end = OBD_OBJECT_EOF;
	else
		policy.l_extent.end = end | ~PAGE_MASK;

	rc = ldlm_cli_enqueue_local(env, ns, res_id, LDLM_EXTENT, &policy,
				    mode, flags, ldlm_blocking_ast,
				    ldlm_completion_ast, ldlm_glimpse_ast,
				    NULL, 0, LVB_T_NONE, NULL, lh);
	RETURN(rc == ELDLM_OK ? 0 : -EIO);
}
EXPORT_SYMBOL(tgt_extent_lock);

static int tgt_data_lock(const struct lu_env *env, struct obd_export *exp,
			 struct ldlm_res_id *res_id, __u64 start, __u64 end,
			 struct lustre_handle *lh, enum ldlm_mode mode)
{
	struct ldlm_namespace *ns = exp->exp_obd->obd_namespace;
	__u64 flags = 0;

	/* MDT IO for data-on-mdt */
	if (exp->exp_connect_data.ocd_connect_flags & OBD_CONNECT_IBITS)
		return tgt_mdt_data_lock(ns, res_id, lh, mode, &flags);

	return tgt_extent_lock(env, ns, res_id, start, end, lh, mode, &flags);
}

void tgt_data_unlock(struct lustre_handle *lh, enum ldlm_mode mode)
{
	LASSERT(lustre_handle_is_used(lh));
	ldlm_lock_decref(lh, mode);
}
EXPORT_SYMBOL(tgt_data_unlock);

static int tgt_brw_lock(const struct lu_env *env, struct obd_export *exp,
			struct ldlm_res_id *res_id, struct obd_ioobj *obj,
			struct niobuf_remote *nb, struct lustre_handle *lh,
			enum ldlm_mode mode)
{
	int nrbufs = obj->ioo_bufcnt;
	int i;

	ENTRY;

	LASSERT(mode == LCK_PR || mode == LCK_PW);
	LASSERT(!lustre_handle_is_used(lh));

	if (test_bit(OBDF_RECOVERING, exp->exp_obd->obd_flags))
		RETURN(0);

	if (nrbufs == 0 || !(nb[0].rnb_flags & OBD_BRW_SRVLOCK))
		RETURN(0);

	for (i = 1; i < nrbufs; i++)
		if (!(nb[i].rnb_flags & OBD_BRW_SRVLOCK))
			RETURN(-EFAULT);

	return tgt_data_lock(env, exp, res_id, nb[0].rnb_offset,
			     nb[nrbufs - 1].rnb_offset +
			     nb[nrbufs - 1].rnb_len - 1, lh, mode);
}

static void tgt_brw_unlock(struct obd_export *exp, struct obd_ioobj *obj,
			   struct niobuf_remote *niob,
			   struct lustre_handle *lh, enum ldlm_mode mode)
{
	ENTRY;

	LASSERT(mode == LCK_PR || mode == LCK_PW);
	LASSERT((!test_bit(OBDF_RECOVERING, exp->exp_obd->obd_flags) && obj->ioo_bufcnt &&
		 niob[0].rnb_flags & OBD_BRW_SRVLOCK) ==
		lustre_handle_is_used(lh));

	if (lustre_handle_is_used(lh))
		tgt_data_unlock(lh, mode);
	EXIT;
}

static int tgt_checksum_niobuf(struct lu_target *tgt,
				 struct niobuf_local *local_nb, int npages,
				 int opc, enum cksum_types cksum_type,
				 __u32 *cksum)
{
	unsigned char cfs_alg = cksum_obd2cfs(cksum_type);
	struct ahash_request *req;
	unsigned int bufsize;
	int i;

	req = cfs_crypto_hash_init(cfs_alg, NULL, 0);
	if (IS_ERR(req)) {
		CERROR("%s: unable to initialize checksum hash %s\n",
		       tgt_name(tgt), cfs_crypto_hash_name(cfs_alg));
		return PTR_ERR(req);
	}

	CDEBUG(D_INFO, "Checksum for algo %s\n", cfs_crypto_hash_name(cfs_alg));
	for (i = 0; i < npages; i++) {
		/* corrupt the data before we compute the checksum, to
		 * simulate a client->OST data error */
		if (i == 0 && opc == OST_WRITE &&
		    CFS_FAIL_CHECK(OBD_FAIL_OST_CHECKSUM_RECEIVE)) {
			int off = local_nb[i].lnb_page_offset & ~PAGE_MASK;
			int len = local_nb[i].lnb_len;
			struct page *np = tgt_page_to_corrupt;

			if (np) {
				char *ptr = kmap_local_page(local_nb[i].lnb_page);
				char *ptr2 = kmap_local_page(np);

				memcpy(ptr2 + off, ptr + off, len);
				memcpy(ptr2 + off, "bad3", min(4, len));
				kunmap_local(ptr2);
				kunmap_local(ptr);

				/* LU-8376 to preserve original index for
				 * display in dump_all_bulk_pages() */
				np->index = i;

				cfs_crypto_hash_update_page(req, np, off,
							    len);
				continue;
			} else {
				CERROR("%s: can't alloc page for corruption\n",
				       tgt_name(tgt));
			}
		}
		cfs_crypto_hash_update_page(req, local_nb[i].lnb_page,
				  local_nb[i].lnb_page_offset & ~PAGE_MASK,
				  local_nb[i].lnb_len);

		 /* corrupt the data after we compute the checksum, to
		 * simulate an OST->client data error */
		if (i == 0 && opc == OST_READ &&
		    CFS_FAIL_CHECK(OBD_FAIL_OST_CHECKSUM_SEND)) {
			int off = local_nb[i].lnb_page_offset & ~PAGE_MASK;
			int len = local_nb[i].lnb_len;
			struct page *np = tgt_page_to_corrupt;

			if (np) {
				char *ptr = kmap_local_page(local_nb[i].lnb_page);
				char *ptr2 = kmap_local_page(np);

				memcpy(ptr2 + off, ptr + off, len);
				memcpy(ptr2 + off, "bad4", min(4, len));
				kunmap_local(ptr2);
				kunmap_local(ptr);

				/* LU-8376 to preserve original index for
				 * display in dump_all_bulk_pages() */
				np->index = i;

				cfs_crypto_hash_update_page(req, np, off,
							    len);
				continue;
			} else {
				CERROR("%s: can't alloc page for corruption\n",
				       tgt_name(tgt));
			}
		}
	}

	bufsize = sizeof(*cksum);
	cfs_crypto_hash_final(req, (unsigned char *)cksum, &bufsize);

	return 0;
}

static void dump_all_bulk_pages(struct obdo *oa, int count,
				struct niobuf_local *local_nb,
				__u32 server_cksum, __u32 client_cksum)
{
	char *dbgcksum_file_name;
	struct file *filp;
	int rc, i;
	unsigned int len;
	char *buf;

	OBD_ALLOC(dbgcksum_file_name, PATH_MAX);
	if (!dbgcksum_file_name)
		return;

	/* will only keep dump of pages on first error for the same range in
	 * file/fid, not during the resends/retries. */
	snprintf(dbgcksum_file_name, PATH_MAX,
		 "%s-checksum_dump-ost-"DFID":[%llu-%llu]-%x-%x",
		 (strncmp(libcfs_debug_file_path, "NONE", 4) != 0 ?
		  libcfs_debug_file_path : LIBCFS_DEBUG_FILE_PATH_DEFAULT),
		 oa->o_valid & OBD_MD_FLFID ? oa->o_parent_seq : (__u64)0,
		 oa->o_valid & OBD_MD_FLFID ? oa->o_parent_oid : 0,
		 oa->o_valid & OBD_MD_FLFID ? oa->o_parent_ver : 0,
		 local_nb[0].lnb_file_offset,
		 local_nb[count-1].lnb_file_offset +
		 local_nb[count-1].lnb_len - 1, client_cksum, server_cksum);
	CWARN("dumping checksum data to %s\n", dbgcksum_file_name);
	filp = filp_open(dbgcksum_file_name,
			 O_CREAT | O_EXCL | O_WRONLY | O_LARGEFILE, 0600);
	if (IS_ERR(filp)) {
		rc = PTR_ERR(filp);
		if (rc == -EEXIST)
			CDEBUG(D_INFO, "%s: can't open to dump pages with "
			       "checksum error: rc = %d\n", dbgcksum_file_name,
			       rc);
		else
			CERROR("%s: can't open to dump pages with checksum "
			       "error: rc = %d\n", dbgcksum_file_name, rc);
		OBD_FREE(dbgcksum_file_name, PATH_MAX);
		return;
	}

	for (i = 0; i < count; i++) {
		void *addr = kmap(local_nb[i].lnb_page);

		len = local_nb[i].lnb_len;
		buf = addr;
		while (len != 0) {
			rc = cfs_kernel_write(filp, buf, len, &filp->f_pos);
			if (rc < 0) {
				CERROR("%s: wanted to write %u but got %d "
				       "error\n", dbgcksum_file_name, len, rc);
				break;
			}
			len -= rc;
			buf += rc;
		}
		kunmap(kmap_to_page(addr));
	}

	rc = vfs_fsync_range(filp, 0, LLONG_MAX, 1);
	if (rc)
		CERROR("%s: sync returns %d\n", dbgcksum_file_name, rc);
	filp_close(filp, NULL);

	libcfs_debug_dumplog();
	OBD_FREE(dbgcksum_file_name, PATH_MAX);
}

static int check_read_checksum(struct niobuf_local *local_nb, int npages,
			       struct obd_export *exp, struct obdo *oa,
			       const struct lnet_processid *peer,
			       __u32 client_cksum, __u32 server_cksum,
			       enum cksum_types server_cksum_type)
{
	char *msg;
	enum cksum_types cksum_type;
	loff_t start, end;

	if (unlikely(npages <= 0))
		return 0;

	/* unlikely to happen and only if resend does not occur due to cksum
	 * control failure on Client */
	if (unlikely(server_cksum == client_cksum)) {
		CDEBUG(D_PAGE, "checksum %x confirmed upon retry\n",
		       client_cksum);
		return 0;
	}

	if (exp->exp_obd->obd_checksum_dump)
		dump_all_bulk_pages(oa, npages, local_nb, server_cksum,
				    client_cksum);

	cksum_type = obd_cksum_type_unpack(oa->o_valid & OBD_MD_FLFLAGS ?
					   oa->o_flags : 0);

	if (cksum_type != server_cksum_type)
		msg = "the server may have not used the checksum type specified in the original request - likely a protocol problem";
	else
		msg = "should have changed on the client or in transit";

	start = local_nb[0].lnb_file_offset;
	end = local_nb[npages-1].lnb_file_offset +
					local_nb[npages-1].lnb_len - 1;

	LCONSOLE_ERROR("%s: BAD READ CHECKSUM: %s: from %s inode " DFID " object "DOSTID" extent [%llu-%llu], client returned csum %x (type %x), server csum %x (type %x)\n",
		       exp->exp_obd->obd_name,
		       msg, libcfs_nidstr(&peer->nid),
		       oa->o_valid & OBD_MD_FLFID ? oa->o_parent_seq : 0ULL,
		       oa->o_valid & OBD_MD_FLFID ? oa->o_parent_oid : 0,
		       oa->o_valid & OBD_MD_FLFID ? oa->o_parent_ver : 0,
		       POSTID(&oa->o_oi),
		       start, end, client_cksum, cksum_type, server_cksum,
		       server_cksum_type);

	return 1;
}

static int tgt_pages2shortio(struct niobuf_local *local, int npages,
			     unsigned char *buf, int size)
{
	int	i, off, len, copied = size;
	char	*ptr;

	for (i = 0; i < npages; i++) {
		off = local[i].lnb_page_offset & ~PAGE_MASK;
		len = local[i].lnb_len;

		CDEBUG(D_PAGE, "index %d offset = %d len = %d left = %d\n",
		       i, off, len, size);
		if (len > size)
			return -EINVAL;

		ptr = kmap_local_page(local[i].lnb_page);
		memcpy(buf, ptr + off, len);
		kunmap_local(ptr);
		buf += len;
		size -= len;
	}
	return copied - size;
}

static int tgt_checksum_niobuf_t10pi(struct lu_target *tgt,
				     enum cksum_types cksum_type,
				     struct niobuf_local *local_nb, int npages,
				     int opc, obd_dif_csum_fn *fn,
				     int sector_size, u32 *check_sum,
				     bool resend)
{
	enum cksum_types t10_cksum_type = tgt->lut_dt_conf.ddp_t10_cksum_type;
	unsigned char cfs_alg = cksum_obd2cfs(OBD_CKSUM_T10_TOP);
	const char *obd_name = tgt->lut_obd->obd_name;
	struct ahash_request *req;
	unsigned char *buffer;
	struct page *__page;
	__be16 *guard_start;
	int guard_number;
	int used_number = 0;
	__u32 cksum;
	unsigned int bufsize = sizeof(cksum);
	int rc = 0, rc2;
	int used;
	int i;

	__page = alloc_page(GFP_KERNEL);
	if (__page == NULL)
		return -ENOMEM;

	req = cfs_crypto_hash_init(cfs_alg, NULL, 0);
	if (IS_ERR(req)) {
		rc = PTR_ERR(req);
		CERROR("%s: unable to initialize checksum hash %s: rc = %d\n",
		       tgt_name(tgt), cfs_crypto_hash_name(cfs_alg), rc);
		goto out;
	}

	buffer = kmap(__page);
	guard_start = (__be16 *)buffer;
	guard_number = PAGE_SIZE / sizeof(*guard_start);
	if (unlikely(resend))
		CDEBUG(D_PAGE | D_HA, "GRD tags per page = %u\n", guard_number);
	for (i = 0; i < npages; i++) {
		bool use_t10_grd;
		int off = local_nb[i].lnb_page_offset & ~PAGE_MASK;
		int len = local_nb[i].lnb_len;
		int guards_needed = DIV_ROUND_UP(off + len, sector_size) -
					(off / sector_size);

		if (guards_needed > guard_number - used_number) {
			cfs_crypto_hash_update_page(req, __page, 0,
				used_number * sizeof(*guard_start));
			used_number = 0;
		}

		/* corrupt the data before we compute the checksum, to
		 * simulate a client->OST data error */
		if (i == 0 && opc == OST_WRITE &&
		    CFS_FAIL_CHECK(OBD_FAIL_OST_CHECKSUM_RECEIVE)) {
			struct page *np = tgt_page_to_corrupt;

			if (np) {
				char *ptr = kmap_local_page(local_nb[i].lnb_page);
				char *ptr2 = kmap_local_page(np);

				memcpy(ptr2 + off, ptr + off, len);
				memcpy(ptr2 + off, "bad3", min(4, len));
				kunmap_local(ptr2);
				kunmap_local(ptr);

				/* LU-8376 to preserve original index for
				 * display in dump_all_bulk_pages() */
				np->index = i;

				cfs_crypto_hash_update_page(req, np, off,
							    len);
				continue;
			} else {
				CERROR("%s: can't alloc page for corruption\n",
				       tgt_name(tgt));
			}
		}

		/*
		 * The left guard number should be able to hold checksums of a
		 * whole page
		 */
		use_t10_grd = t10_cksum_type && t10_cksum_type == cksum_type &&
			      opc == OST_READ &&
			      local_nb[i].lnb_len == PAGE_SIZE &&
			      local_nb[i].lnb_guard_disk;
		if (use_t10_grd) {
			used = guards_needed;
			if (used > (guard_number - used_number)) {
				rc = -E2BIG;
				CDEBUG(D_PAGE | D_HA,
				       "%s: used %u, guard %u/%u, data size %u+%u, sector_size %u: rc = %d\n",
				       obd_name, used, guard_number,
				       used_number, local_nb[i].lnb_page_offset,
				       local_nb[i].lnb_len, sector_size, rc);
				break;
			}
			memcpy(guard_start + used_number,
			       local_nb[i].lnb_guards,
			       used * sizeof(*guard_start));
			if (unlikely(resend))
				CDEBUG(D_PAGE | D_HA,
				       "lnb[%u]: used %u off %u+%u lnb checksum: %*phN\n",
				       i, used,
				       local_nb[i].lnb_page_offset,
				       local_nb[i].lnb_len,
				       (int)(used * sizeof(*guard_start)),
				       guard_start + used_number);
		}
		if (!use_t10_grd || unlikely(resend)) {
			__be16 guard_tmp[MAX_GUARD_NUMBER];
			__be16 *guards = guard_start + used_number;
			int used_tmp = -1, *usedp = &used;

			if (unlikely(use_t10_grd)) {
				guards = guard_tmp;
				usedp = &used_tmp;
			}
			rc = obd_page_dif_generate_buffer(obd_name,
				local_nb[i].lnb_page,
				local_nb[i].lnb_page_offset & ~PAGE_MASK,
				local_nb[i].lnb_len, guards,
				guard_number - used_number, usedp, sector_size,
				fn);
			if (unlikely(resend)) {
				bool bad = use_t10_grd &&
					memcmp(guard_tmp,
					       local_nb[i].lnb_guards,
					       used_tmp * sizeof(*guard_tmp));

				if (bad)
					CERROR("lnb[%u]: used %u/%u off %u+%u tmp checksum: %*phN\n",
					       i, used, used_tmp,
					       local_nb[i].lnb_page_offset,
					       local_nb[i].lnb_len,
					       (int)(used_tmp * sizeof(*guard_start)),
					       guard_tmp);
				CDEBUG_LIMIT(D_PAGE | D_HA | (bad ? D_ERROR : 0),
				       "lnb[%u]: used %u/%u off %u+%u gen checksum: %*phN\n",
				       i, used, used_tmp,
				       local_nb[i].lnb_page_offset,
				       local_nb[i].lnb_len,
				       (int)(used * sizeof(*guard_start)),
				       guard_start + used_number);
			}
			if (rc)
				break;
		}

		LASSERT(used <= MAX_GUARD_NUMBER);
		/*
		 * If disk support T10PI checksum, copy guards to local_nb.
		 * If the write is partial page, do not use the guards for bio
		 * submission since the data might not be full-sector. The bio
		 * guards will be generated later based on the full sectors. If
		 * the sector size is 512B rather than 4 KB, or the page size
		 * is larger than 4KB, this might drop some useful guards for
		 * partial page write, but it will only add minimal extra time
		 * of checksum calculation.
		 */
		if (t10_cksum_type && t10_cksum_type == cksum_type &&
		    opc == OST_WRITE &&
		    local_nb[i].lnb_len == PAGE_SIZE) {
			local_nb[i].lnb_guard_rpc = 1;
			memcpy(local_nb[i].lnb_guards,
			       guard_start + used_number,
			       used * sizeof(*local_nb[i].lnb_guards));
		}

		used_number += used;

		 /* corrupt the data after we compute the checksum, to
		 * simulate an OST->client data error */
		if (unlikely(i == 0 && opc == OST_READ &&
			     CFS_FAIL_CHECK(OBD_FAIL_OST_CHECKSUM_SEND))) {
			struct page *np = tgt_page_to_corrupt;

			if (np) {
				char *ptr = kmap_local_page(local_nb[i].lnb_page);
				char *ptr2 = kmap_local_page(np);

				memcpy(ptr2 + off, ptr + off, len);
				memcpy(ptr2 + off, "bad4", min(4, len));
				kunmap_local(ptr2);
				kunmap_local(ptr);

				/* LU-8376 to preserve original index for
				 * display in dump_all_bulk_pages() */
				np->index = i;

				cfs_crypto_hash_update_page(req, np, off,
							    len);
				continue;
			} else {
				CERROR("%s: can't alloc page for corruption\n",
				       tgt_name(tgt));
			}
		}
	}
	kunmap(kmap_to_page(buffer));
	if (rc)
		GOTO(out_hash, rc);

	if (used_number != 0)
		cfs_crypto_hash_update_page(req, __page, 0,
					    used_number * sizeof(*guard_start));
out_hash:
	rc2 = cfs_crypto_hash_final(req, (unsigned char *)&cksum, &bufsize);
	if (!rc)
		rc = rc2;
	if (rc == 0)
		*check_sum = cksum;
out:
	__free_page(__page);
	return rc;
}

static int tgt_checksum_niobuf_rw(struct lu_target *tgt,
				  enum cksum_types cksum_type,
				  struct niobuf_local *local_nb,
				  int npages, int opc, u32 *check_sum,
				  bool resend)
{
	obd_dif_csum_fn *fn = NULL;
	int sector_size = 0;
	int rc;

	ENTRY;
	obd_t10_cksum2dif(cksum_type, &fn, &sector_size);

	if (fn)
		rc = tgt_checksum_niobuf_t10pi(tgt, cksum_type,
					       local_nb, npages,
					       opc, fn, sector_size,
					       check_sum, resend);
	else
		rc = tgt_checksum_niobuf(tgt, local_nb, npages, opc,
					 cksum_type, check_sum);

	RETURN(rc);
}

int tgt_brw_read(struct tgt_session_info *tsi)
{
	struct ptlrpc_request	*req = tgt_ses_req(tsi);
	struct ptlrpc_bulk_desc	*desc = NULL;
	struct obd_export	*exp = tsi->tsi_exp;
	struct niobuf_remote	*remote_nb;
	struct niobuf_local	*local_nb;
	struct obd_ioobj	*ioo;
	struct ost_body		*body, *repbody;
	struct lustre_handle	 lockh = { 0 };
	int			 npages, nob = 0, rc, i, no_reply = 0,
				 npages_read;
	struct tgt_thread_big_cache *tbc = req->rq_svc_thread->t_data;
	const char *obd_name = exp->exp_obd->obd_name;
	ktime_t kstart;

	ENTRY;

	if (ptlrpc_req2svc(req)->srv_req_portal != OST_IO_PORTAL &&
	    ptlrpc_req2svc(req)->srv_req_portal != MDS_IO_PORTAL) {
		CERROR("%s: deny read request from %s to portal %u\n",
		       tgt_name(tsi->tsi_tgt),
		       obd_export_nid2str(req->rq_export),
		       ptlrpc_req2svc(req)->srv_req_portal);
		RETURN(-EPROTO);
	}

	req->rq_bulk_read = 1;

	if (CFS_FAIL_CHECK(OBD_FAIL_OST_BRW_READ_BULK)) {
		/* optionally use cfs_fail_val - 1 to select a specific OST on
		 * this server to fail requests.
		 */
		char fail_ost_name[MAX_OBD_NAME];

		if (cfs_fail_val > 0) {
			snprintf(fail_ost_name, MAX_OBD_NAME, "OST%04X",
				 cfs_fail_val - 1);

			if (strstr(obd_name, fail_ost_name))
				RETURN(err_serious(-EIO));
		} else {
			RETURN(err_serious(-EIO));
		}
	}

	CFS_FAIL_TIMEOUT(OBD_FAIL_OST_BRW_PAUSE_BULK, cfs_fail_val > 0 ?
			 cfs_fail_val : (obd_timeout + 1) / 4);

	/* There must be big cache in current thread to process this request
	 * if it is NULL then something went wrong and it wasn't allocated,
	 * report -ENOMEM in that case */
	if (tbc == NULL)
		RETURN(-ENOMEM);

	body = tsi->tsi_ost_body;
	LASSERT(body != NULL);

	if (body->oa.o_valid & OBD_MD_FLFLAGS &&
	    body->oa.o_flags & OBD_FL_NORPC)
		RETURN(0);

	ioo = req_capsule_client_get(tsi->tsi_pill, &RMF_OBD_IOOBJ);
	LASSERT(ioo != NULL); /* must exists after tgt_ost_body_unpack */

	remote_nb = req_capsule_client_get(&req->rq_pill, &RMF_NIOBUF_REMOTE);
	LASSERT(remote_nb != NULL); /* must exists after tgt_ost_body_unpack */

	local_nb = tbc->local;

	rc = tgt_brw_lock(tsi->tsi_env, exp, &tsi->tsi_resid, ioo, remote_nb,
			  &lockh, LCK_PR);
	if (rc != 0)
		RETURN(rc);

	/*
	 * If getting the lock took more time than
	 * client was willing to wait, drop it. b=11330
	 */
	if (ktime_get_real_seconds() > req->rq_deadline ||
	    CFS_FAIL_CHECK(OBD_FAIL_OST_DROP_REQ)) {
		no_reply = 1;
		CERROR("Dropping timed-out read from %s because locking object " DOSTID " took %lld seconds (limit was %lld).\n",
		       libcfs_idstr(&req->rq_peer), POSTID(&ioo->ioo_oid),
		       ktime_get_real_seconds() - req->rq_arrival_time.tv_sec,
		       req->rq_deadline - req->rq_arrival_time.tv_sec);
		GOTO(out_lock, rc = -ETIMEDOUT);
	}

	/*
	 * Because we already sync grant info with client when
	 * reconnect, grant info will be cleared for resent req,
	 * otherwise, outdated grant count in the rpc would de-sync
	 * grant counters in case of shrink
	 */
	if (lustre_msg_get_flags(req->rq_reqmsg) & (MSG_RESENT | MSG_REPLAY)) {
		DEBUG_REQ(D_CACHE, req, "clear resent/replay req grant info");
		body->oa.o_valid &= ~OBD_MD_FLGRANT;
	}

	repbody = req_capsule_server_get(&req->rq_pill, &RMF_OST_BODY);
	repbody->oa = body->oa;

	npages = PTLRPC_MAX_BRW_PAGES;
	kstart = ktime_get();
	rc = obd_preprw(tsi->tsi_env, OBD_BRW_READ, exp, &repbody->oa, 1,
			ioo, remote_nb, &npages, local_nb);
	if (rc != 0)
		GOTO(out_lock, rc);

	if (body->oa.o_valid & OBD_MD_FLFLAGS &&
	    body->oa.o_flags & OBD_FL_SHORT_IO) {
		desc = NULL;
	} else {
		desc = ptlrpc_prep_bulk_exp(req, npages, ioobj_max_brw_get(ioo),
					    PTLRPC_BULK_PUT_SOURCE,
					    OST_BULK_PORTAL,
					    &ptlrpc_bulk_kiov_nopin_ops);
		if (desc == NULL)
			GOTO(out_commitrw, rc = -ENOMEM);
		/* client may have MD handling requirements  */
		desc->bd_md_offset = ioobj_page_interop_offset(ioo);
	}

	npages_read = npages;
	for (i = 0; i < npages; i++) {
		int page_rc = local_nb[i].lnb_rc;

		if (page_rc < 0) {
			rc = page_rc;
			npages_read = i;
			break;
		}

		nob += page_rc;
		if (page_rc != 0 && desc != NULL) { /* some data! */
			LASSERT(local_nb[i].lnb_page != NULL);
			CDEBUG(D_INODE,
			       "lnb %d, at offset %llu, hole %d\n", i,
			       local_nb[i].lnb_file_offset,
			       local_nb[i].lnb_hole);
			desc->bd_frag_ops->add_kiov_frag
			  (desc, local_nb[i].lnb_page,
			   local_nb[i].lnb_page_offset & ~PAGE_MASK,
			   page_rc);
		}

		if (page_rc != local_nb[i].lnb_len) { /* short read */
			local_nb[i].lnb_len = page_rc;
			npages_read = i + (page_rc != 0 ? 1 : 0);
			/* All subsequent pages should be 0 */
			while (++i < npages)
				LASSERT(local_nb[i].lnb_rc == 0);
			break;
		}
	}

	if (body->oa.o_valid & OBD_MD_FLCKSUM) {
		u32 flag = body->oa.o_valid & OBD_MD_FLFLAGS ?
			   body->oa.o_flags : 0;
		enum cksum_types cksum_type = obd_cksum_type_unpack(flag);
		bool resend = (body->oa.o_valid & OBD_MD_FLFLAGS) &&
			(body->oa.o_flags & OBD_FL_RECOV_RESEND);

		repbody->oa.o_flags = obd_cksum_type_pack(obd_name,
							  cksum_type);
		repbody->oa.o_valid = OBD_MD_FLCKSUM | OBD_MD_FLFLAGS;

		rc = tgt_checksum_niobuf_rw(tsi->tsi_tgt, cksum_type,
					    local_nb, npages_read, OST_READ,
					    &repbody->oa.o_cksum, resend);
		if (rc < 0)
			GOTO(out_commitrw, rc);
		CDEBUG(D_PAGE | (resend ? D_HA : 0),
		       "checksum at read origin: %x (%x)\n",
		       repbody->oa.o_cksum, cksum_type);

		/* if a resend it could be for a cksum error, so check Server
		 * cksum with returned Client cksum (this should even cover
		 * zero-cksum case) */
		if (resend)
			check_read_checksum(local_nb, npages_read, exp,
					    &body->oa, &req->rq_peer,
					    body->oa.o_cksum,
					    repbody->oa.o_cksum, cksum_type);
	} else {
		repbody->oa.o_valid = 0;
	}
	if (body->oa.o_valid & OBD_MD_FLGRANT)
		repbody->oa.o_valid |= OBD_MD_FLGRANT;
	/* We're finishing using body->oa as an input variable */

	/* Check if client was evicted while we were doing i/o before touching
	 * network */
	if (rc == 0) {
		if (body->oa.o_valid & OBD_MD_FLFLAGS &&
		    body->oa.o_flags & OBD_FL_SHORT_IO) {
			unsigned char *short_io_buf;
			int short_io_size;

			short_io_buf = req_capsule_server_get(&req->rq_pill,
							      &RMF_SHORT_IO);
			short_io_size = req_capsule_get_size(&req->rq_pill,
							     &RMF_SHORT_IO,
							     RCL_SERVER);
			rc = tgt_pages2shortio(local_nb, npages_read,
					       short_io_buf, short_io_size);
			if (rc >= 0)
				req_capsule_shrink(&req->rq_pill,
						   &RMF_SHORT_IO, rc,
						   RCL_SERVER);
			rc = rc > 0 ? 0 : rc;
		} else if (!CFS_FAIL_PRECHECK(OBD_FAIL_PTLRPC_CLIENT_BULK_CB2)) {
			rc = target_bulk_io(exp, desc);
		}
		no_reply = rc != 0;
	} else {
		if (body->oa.o_valid & OBD_MD_FLFLAGS &&
		    body->oa.o_flags & OBD_FL_SHORT_IO)
			req_capsule_shrink(&req->rq_pill, &RMF_SHORT_IO, 0,
					   RCL_SERVER);
	}

out_commitrw:
	/* Must commit after prep above in all cases */
	rc = obd_commitrw(tsi->tsi_env, OBD_BRW_READ, exp, &repbody->oa, 1, ioo,
			  remote_nb, npages, local_nb, rc, nob, kstart);
out_lock:
	tgt_brw_unlock(exp, ioo, remote_nb, &lockh, LCK_PR);

	if (desc && !CFS_FAIL_PRECHECK(OBD_FAIL_PTLRPC_CLIENT_BULK_CB2))
		ptlrpc_free_bulk(desc);

	LASSERT(rc <= 0);
	if (rc == 0) {
		rc = nob;
		ptlrpc_lprocfs_brw(req, nob);
	} else if (no_reply) {
		req->rq_no_reply = 1;
		/* reply out callback would free */
		ptlrpc_req_drop_rs(req);
		LCONSOLE_WARN("%s: Bulk IO read error with %s (at %s), "
			      "client will retry: rc %d\n",
			      obd_name,
			      obd_uuid2str(&exp->exp_client_uuid),
			      obd_export_nid2str(exp), rc);
	}
	/* send a bulk after reply to simulate a network delay or reordering
	 * by a router - Note that !desc implies short io, so there is no bulk
	 * to reorder. */
	if (unlikely(CFS_FAIL_PRECHECK(OBD_FAIL_PTLRPC_CLIENT_BULK_CB2)) &&
	    desc) {
		/* Calculate checksum before request transfer, original
		 * it is done by target_bulk_io() */
		rc = sptlrpc_svc_wrap_bulk(req, desc);
		if (OCD_HAS_FLAG(&exp->exp_connect_data, BULK_MBITS))
			req->rq_mbits = lustre_msg_get_mbits(req->rq_reqmsg);
		else /* old version, bulk matchbits is rq_xid */
			req->rq_mbits = req->rq_xid;

		req->rq_status = rc;
		target_committed_to_req(req);
		target_send_reply(req, 0, 0);

		CDEBUG(D_INFO, "reorder BULK\n");
		CFS_FAIL_TIMEOUT(OBD_FAIL_PTLRPC_CLIENT_BULK_CB2,
				 cfs_fail_val ? : 3);

		target_bulk_io(exp, desc);
		ptlrpc_free_bulk(desc);
	}

	RETURN(rc);
}
EXPORT_SYMBOL(tgt_brw_read);

static int tgt_shortio2pages(struct niobuf_local *local, int npages,
			     unsigned char *buf, unsigned int size)
{
	int	i, off, len;
	char	*ptr;

	for (i = 0; i < npages; i++) {
		off = local[i].lnb_page_offset & ~PAGE_MASK;
		len = local[i].lnb_len;

		if (len == 0)
			continue;

		CDEBUG(D_PAGE, "index %d offset = %d len = %d left = %d\n",
		       i, off, len, size);
		ptr = kmap_local_page(local[i].lnb_page);
		memcpy(ptr + off, buf, len < size ? len : size);
		kunmap_local(ptr);
		buf += len;
		size -= len;
	}
	return 0;
}

static void tgt_warn_on_cksum(struct ptlrpc_request *req,
			      struct ptlrpc_bulk_desc *desc,
			      struct niobuf_local *local_nb, int npages,
			      u32 client_cksum, u32 server_cksum,
			      bool mmap)
{
	struct obd_export *exp = req->rq_export;
	struct ost_body *body;
	char *router = "";
	char *via = "";

	body = req_capsule_client_get(&req->rq_pill, &RMF_OST_BODY);
	LASSERT(body != NULL);

	if (desc && !nid_same(&req->rq_peer.nid, &desc->bd_sender)) {
		via = " via ";
		router = libcfs_nidstr(&desc->bd_sender);
	}

	if (exp->exp_obd->obd_checksum_dump)
		dump_all_bulk_pages(&body->oa, npages, local_nb, server_cksum,
				    client_cksum);

	if (mmap) {
		CDEBUG_LIMIT(D_INFO, "client csum %x, server csum %x\n",
			     client_cksum, server_cksum);
		return;
	}

	LCONSOLE_ERROR("%s: BAD WRITE CHECKSUM: from %s%s%s inode " DFID " object " DOSTID " extent [%llu-%llu]: client csum %x, server csum %x\n",
		       exp->exp_obd->obd_name, libcfs_idstr(&req->rq_peer),
		       via, router,
		       body->oa.o_valid & OBD_MD_FLFID ?
		       body->oa.o_parent_seq : (__u64)0,
		       body->oa.o_valid & OBD_MD_FLFID ?
		       body->oa.o_parent_oid : 0,
		       body->oa.o_valid & OBD_MD_FLFID ?
		       body->oa.o_parent_ver : 0,
		       POSTID(&body->oa.o_oi),
		       local_nb[0].lnb_file_offset,
		       local_nb[npages-1].lnb_file_offset +
		       local_nb[npages - 1].lnb_len - 1,
		       client_cksum, server_cksum);
}

int tgt_brw_write(struct tgt_session_info *tsi)
{
	struct ptlrpc_request	*req = tgt_ses_req(tsi);
	struct ptlrpc_bulk_desc	*desc = NULL;
	struct obd_export	*exp = req->rq_export;
	struct niobuf_remote	*remote_nb;
	struct niobuf_local	*local_nb;
	struct obd_ioobj	*ioo;
	struct ost_body		*body, *repbody;
	struct lustre_handle	 lockh = {0};
	__u32			*rcs;
	int			 objcount, niocount, npages;
	int			 rc = 0;
	int			 i, j;
	enum cksum_types cksum_type = OBD_CKSUM_CRC32;
	bool			 no_reply = false, mmap;
	struct tgt_thread_big_cache *tbc = req->rq_svc_thread->t_data;
	bool wait_sync = false;
	const char *obd_name = exp->exp_obd->obd_name;
	/* '1' for consistency with code that checks !mpflag to restore */
	unsigned int mpflags = 1;
	ktime_t kstart;
	int nob = 0;

	ENTRY;

	if (ptlrpc_req2svc(req)->srv_req_portal != OST_IO_PORTAL &&
	    ptlrpc_req2svc(req)->srv_req_portal != MDS_IO_PORTAL) {
		CERROR("%s: deny write request from %s to portal %u\n",
		       tgt_name(tsi->tsi_tgt),
		       obd_export_nid2str(req->rq_export),
		       ptlrpc_req2svc(req)->srv_req_portal);
		RETURN(err_serious(-EPROTO));
	}

	if (CFS_FAIL_CHECK(OBD_FAIL_OST_ENOSPC))
		RETURN(err_serious(-ENOSPC));
	if (CFS_FAIL_TIMEOUT(OBD_FAIL_OST_EROFS, 1))
		RETURN(err_serious(cfs_fail_val ? -cfs_fail_val : -EROFS));

	req->rq_bulk_write = 1;

	if (CFS_FAIL_CHECK(OBD_FAIL_OST_BRW_WRITE_BULK))
		rc = -EIO;
	if (CFS_FAIL_CHECK(OBD_FAIL_OST_BRW_WRITE_BULK2))
		rc = -EFAULT;
	if (rc < 0) {
		/* optionally use cfs_fail_val - 1 to select a specific OST on
		 * this server to fail requests.
		 */
		char fail_ost_name[MAX_OBD_NAME];

		if (cfs_fail_val > 0) {
			snprintf(fail_ost_name, MAX_OBD_NAME, "OST%04X",
				 cfs_fail_val - 1);

			if (strstr(obd_name, fail_ost_name))
				RETURN(err_serious(rc));
		} else {
			RETURN(err_serious(rc));
		}
	}

	/* pause before transaction has been started */
	CFS_FAIL_TIMEOUT(OBD_FAIL_OST_BRW_PAUSE_BULK, cfs_fail_val > 0 ?
			 cfs_fail_val : (obd_timeout + 1) / 4);

	/* Delay write commit to show stale size information */
	CFS_FAIL_TIMEOUT(OBD_FAIL_OSC_NO_SIZE_DATA, cfs_fail_val);

	/* There must be big cache in current thread to process this request
	 * if it is NULL then something went wrong and it wasn't allocated,
	 * report -ENOMEM in that case */
	if (tbc == NULL)
		RETURN(-ENOMEM);

	body = tsi->tsi_ost_body;
	LASSERT(body != NULL);

	if (body->oa.o_valid & OBD_MD_FLFLAGS &&
	    body->oa.o_flags & OBD_FL_NORPC)
		RETURN(0);


	ioo = req_capsule_client_get(&req->rq_pill, &RMF_OBD_IOOBJ);
	LASSERT(ioo != NULL); /* must exists after tgt_ost_body_unpack */

	objcount = req_capsule_get_size(&req->rq_pill, &RMF_OBD_IOOBJ,
					RCL_CLIENT) / sizeof(*ioo);

	for (niocount = i = 0; i < objcount; i++)
		niocount += ioo[i].ioo_bufcnt;

	remote_nb = req_capsule_client_get(&req->rq_pill, &RMF_NIOBUF_REMOTE);
	LASSERT(remote_nb != NULL); /* must exists after tgt_ost_body_unpack */
	if (niocount != req_capsule_get_size(&req->rq_pill,
					     &RMF_NIOBUF_REMOTE, RCL_CLIENT) /
			sizeof(*remote_nb))
		RETURN(err_serious(-EPROTO));

	if ((remote_nb[0].rnb_flags & OBD_BRW_MEMALLOC) &&
	    ptlrpc_connection_is_local(exp->exp_connection))
		mpflags = memalloc_noreclaim_save();

	/* it is incorrect to return ENOSPC when granted space has been used */
	if (unlikely(!(remote_nb[0].rnb_flags & OBD_BRW_FROM_GRANT))) {
		if (CFS_FAIL_CHECK(OBD_FAIL_OST_ENOSPC_VALID))
			RETURN(err_serious(-ENOSPC));
	}

	req_capsule_set_size(&req->rq_pill, &RMF_RCS, RCL_SERVER,
			     niocount * sizeof(*rcs));
	rc = req_capsule_server_pack(&req->rq_pill);
	if (rc != 0)
		GOTO(out, rc = err_serious(rc));

	CFS_FAIL_TIMEOUT(OBD_FAIL_OST_BRW_PAUSE_PACK, cfs_fail_val);
	rcs = req_capsule_server_get(&req->rq_pill, &RMF_RCS);

	local_nb = tbc->local;

	rc = tgt_brw_lock(tsi->tsi_env, exp, &tsi->tsi_resid, ioo, remote_nb,
			  &lockh, LCK_PW);
	if (rc != 0)
		GOTO(out, rc);

	/*
	 * If getting the lock took more time than
	 * client was willing to wait, drop it. b=11330
	 */
	if (ktime_get_real_seconds() > req->rq_deadline ||
	    CFS_FAIL_CHECK(OBD_FAIL_OST_DROP_REQ)) {
		no_reply = true;
		CERROR("%s: Dropping timed-out write from %s because locking object " DOSTID " took %lld seconds (limit was %lld).\n",
		       tgt_name(tsi->tsi_tgt), libcfs_idstr(&req->rq_peer),
		       POSTID(&ioo->ioo_oid),
		       ktime_get_real_seconds() - req->rq_arrival_time.tv_sec,
		       req->rq_deadline - req->rq_arrival_time.tv_sec);
		GOTO(out_lock, rc = -ETIMEDOUT);
	}

	/* Because we already sync grant info with client when reconnect,
	 * grant info will be cleared for resent req, then fed_grant and
	 * total_grant will not be modified in following preprw_write */
	if (lustre_msg_get_flags(req->rq_reqmsg) & (MSG_RESENT | MSG_REPLAY)) {
		DEBUG_REQ(D_CACHE, req, "clear resent/replay req grant info");
		body->oa.o_valid &= ~OBD_MD_FLGRANT;
	}

	repbody = req_capsule_server_get(&req->rq_pill, &RMF_OST_BODY);
	if (repbody == NULL)
		GOTO(out_lock, rc = -ENOMEM);
	repbody->oa = body->oa;

	npages = PTLRPC_MAX_BRW_PAGES;
	kstart = ktime_get();
	rc = obd_preprw(tsi->tsi_env, OBD_BRW_WRITE, exp, &repbody->oa,
			objcount, ioo, remote_nb, &npages, local_nb);
	if (rc < 0)
		GOTO(out_lock, rc);
	if (body->oa.o_valid & OBD_MD_FLFLAGS &&
	    body->oa.o_flags & OBD_FL_SHORT_IO) {
		unsigned int short_io_size;
		unsigned char *short_io_buf;

		short_io_size = req_capsule_get_size(&req->rq_pill,
						     &RMF_SHORT_IO,
						     RCL_CLIENT);
		short_io_buf = req_capsule_client_get(&req->rq_pill,
						      &RMF_SHORT_IO);
		CDEBUG(D_INFO, "Client use short io for data transfer,"
			       " size = %d\n", short_io_size);

		/* Copy short io buf to pages */
		rc = tgt_shortio2pages(local_nb, npages, short_io_buf,
				       short_io_size);
		desc = NULL;
	} else {
		desc = ptlrpc_prep_bulk_exp(req, npages, ioobj_max_brw_get(ioo),
					    PTLRPC_BULK_GET_SINK,
					    OST_BULK_PORTAL,
					    &ptlrpc_bulk_kiov_nopin_ops);
		if (desc == NULL)
			GOTO(skip_transfer, rc = -ENOMEM);
		/* client may have MD handling requirements  */
		desc->bd_md_offset = ioobj_page_interop_offset(ioo);

		/* NB Having prepped, we must commit... */
		for (i = 0; i < npages; i++)
			desc->bd_frag_ops->add_kiov_frag(desc,
					local_nb[i].lnb_page,
					local_nb[i].lnb_page_offset & ~PAGE_MASK,
					local_nb[i].lnb_len);

		rc = sptlrpc_svc_prep_bulk(req, desc);
		if (rc != 0)
			GOTO(skip_transfer, rc);

		rc = target_bulk_io(exp, desc);
	}

	no_reply = rc != 0;

skip_transfer:
	if (body->oa.o_valid & OBD_MD_FLCKSUM && rc == 0) {
		static int cksum_counter;

		if (body->oa.o_valid & OBD_MD_FLFLAGS)
			cksum_type = obd_cksum_type_unpack(body->oa.o_flags);

		repbody->oa.o_valid |= OBD_MD_FLCKSUM | OBD_MD_FLFLAGS;
		repbody->oa.o_flags &= ~OBD_FL_CKSUM_ALL;
		repbody->oa.o_flags |= obd_cksum_type_pack(obd_name,
							   cksum_type);

		rc = tgt_checksum_niobuf_rw(tsi->tsi_tgt, cksum_type,
					    local_nb, npages, OST_WRITE,
					    &repbody->oa.o_cksum, false);
		if (rc < 0)
			GOTO(out_commitrw, rc);

		cksum_counter++;

		if (unlikely(body->oa.o_cksum != repbody->oa.o_cksum)) {
			mmap = (body->oa.o_valid & OBD_MD_FLFLAGS &&
				body->oa.o_flags & OBD_FL_MMAP);

			tgt_warn_on_cksum(req, desc, local_nb, npages,
					  body->oa.o_cksum,
					  repbody->oa.o_cksum, mmap);
			cksum_counter = 0;
		} else if ((cksum_counter & (-cksum_counter)) ==
			   cksum_counter) {
			CDEBUG(D_INFO, "Checksum %u from %s OK: %x\n",
			       cksum_counter, libcfs_idstr(&req->rq_peer),
			       repbody->oa.o_cksum);
		}
	}

	CFS_FAIL_TIMEOUT(OBD_FAIL_OST_BRW_PAUSE_BULK2, cfs_fail_val);

out_commitrw:
	/* calculate the expected actual write bytes (nob) for OFD stats.
	 * Technically, if commit fails this would be wrong, but that should be
	 * very rare
	 */
	for (i = 0; i < niocount; i++) {
		int len = remote_nb[i].rnb_len;

		nob += len;
	}

	/* multiple transactions can be assigned during write commit */
	tsi->tsi_mult_trans = 1;

	/* Must commit after prep above in all cases */
	rc = obd_commitrw(tsi->tsi_env, OBD_BRW_WRITE, exp, &repbody->oa,
			  objcount, ioo, remote_nb, npages, local_nb, rc, nob,
			  kstart);
	if (rc == -ENOTCONN)
		/* quota acquire process has been given up because
		 * either the client has been evicted or the client
		 * has timed out the request already
		 */
		no_reply = true;

	for (i = 0; i < niocount; i++) {
		if (!(local_nb[i].lnb_flags & OBD_BRW_ASYNC)) {
			wait_sync = true;
			break;
		}
	}
	/*
	 * Disable sending mtime back to the client. If the client locked the
	 * whole object, then it has already updated the mtime on its side,
	 * otherwise it will have to glimpse anyway (see bug 21489, comment 32)
	 */
	repbody->oa.o_valid &= ~(OBD_MD_FLMTIME | OBD_MD_FLATIME);

	if (rc == 0) {
		/* set per-requested niobuf return codes */
		for (i = j = 0; i < niocount; i++) {
			int len = remote_nb[i].rnb_len;

			rcs[i] = 0;
			do {
				LASSERT(j < npages);
				if (local_nb[j].lnb_rc < 0)
					rcs[i] = local_nb[j].lnb_rc;
				len -= local_nb[j].lnb_len;
				j++;
			} while (len > 0);
			LASSERT(len == 0);
		}
		LASSERT(j == npages);
		ptlrpc_lprocfs_brw(req, nob);
	}
out_lock:
	tgt_brw_unlock(exp, ioo, remote_nb, &lockh, LCK_PW);
	if (desc)
		ptlrpc_free_bulk(desc);
out:
	if (unlikely(no_reply || (exp->exp_obd->obd_no_transno && wait_sync))) {
		req->rq_no_reply = 1;
		/* reply out callback would free */
		ptlrpc_req_drop_rs(req);
		if (!exp->exp_obd->obd_no_transno)
			LCONSOLE_WARN("%s: Bulk IO write error with %s (at %s),"
				      " client will retry: rc = %d\n",
				      obd_name,
				      obd_uuid2str(&exp->exp_client_uuid),
				      obd_export_nid2str(exp), rc);
	}

	if (mpflags)
		memalloc_noreclaim_restore(mpflags);

	RETURN(rc);
}
EXPORT_SYMBOL(tgt_brw_write);

/**
 * Common request handler for OST_SEEK RPC.
 *
 * Unified request handling for OST_SEEK RPC.
 * It takes object by its FID, does needed lseek and packs result
 * into reply. Only SEEK_HOLE and SEEK_DATA are supported.
 *
 * \param[in] tsi	target session environment for this request
 *
 * \retval		0 if successful
 * \retval		negative value on error
 */
int tgt_lseek(struct tgt_session_info *tsi)
{
	struct lustre_handle lh = { 0 };
	struct dt_object *dob;
	struct ost_body *repbody;
	loff_t offset = tsi->tsi_ost_body->oa.o_size;
	int whence = tsi->tsi_ost_body->oa.o_mode;
	bool srvlock;
	int rc = 0;

	ENTRY;

	if (whence != SEEK_HOLE && whence != SEEK_DATA)
		RETURN(-EPROTO);

	/* Negative offset is prohibited on wire and must be handled on client
	 * prior sending RPC.
	 */
	if (offset < 0)
		RETURN(-EPROTO);

	repbody = req_capsule_server_get(tsi->tsi_pill, &RMF_OST_BODY);
	if (repbody == NULL)
		RETURN(-ENOMEM);
	repbody->oa = tsi->tsi_ost_body->oa;

	srvlock = tsi->tsi_ost_body->oa.o_valid & OBD_MD_FLFLAGS &&
		  tsi->tsi_ost_body->oa.o_flags & OBD_FL_SRVLOCK;
	if (srvlock) {
		rc = tgt_data_lock(tsi->tsi_env, tsi->tsi_exp, &tsi->tsi_resid,
				   offset, OBD_OBJECT_EOF, &lh, LCK_PR);
		if (rc)
			RETURN(rc);
	}

	dob = dt_locate(tsi->tsi_env, tsi->tsi_tgt->lut_bottom, &tsi->tsi_fid);
	if (IS_ERR(dob))
		GOTO(out, rc = PTR_ERR(dob));

	if (!dt_object_exists(dob))
		GOTO(obj_put, rc = -ENOENT);

	repbody->oa.o_size = dt_lseek(tsi->tsi_env, dob, offset, whence);
	rc = 0;
obj_put:
	dt_object_put(tsi->tsi_env, dob);
out:
	if (srvlock)
		tgt_data_unlock(&lh, LCK_PR);

	RETURN(rc);
}
EXPORT_SYMBOL(tgt_lseek);

/* Check if request can be reconstructed from saved reply data
 * A copy of the reply data is returned in @trd if the pointer is not NULL
 */
int req_can_reconstruct(struct ptlrpc_request *req,
			 struct tg_reply_data *trd)
{
	struct tg_export_data *ted = &req->rq_export->exp_target_data;
	struct lsd_client_data *lcd = ted->ted_lcd;
	int found;

	if (tgt_is_multimodrpcs_client(req->rq_export))
		return tgt_lookup_reply(req, trd);

	mutex_lock(&ted->ted_lcd_lock);
	found = req->rq_xid == lcd->lcd_last_xid ||
		req->rq_xid == lcd->lcd_last_close_xid;

	if (found && trd != NULL) {
		if (lustre_msg_get_opc(req->rq_reqmsg) == MDS_CLOSE) {
			trd->trd_reply.lrd_xid = lcd->lcd_last_close_xid;
			trd->trd_reply.lrd_transno =
						lcd->lcd_last_close_transno;
			trd->trd_reply.lrd_result = lcd->lcd_last_close_result;
		} else {
			trd->trd_reply.lrd_xid = lcd->lcd_last_xid;
			trd->trd_reply.lrd_transno = lcd->lcd_last_transno;
			trd->trd_reply.lrd_result = lcd->lcd_last_result;
			trd->trd_reply.lrd_data = lcd->lcd_last_data;
			trd->trd_pre_versions[0] = lcd->lcd_pre_versions[0];
			trd->trd_pre_versions[1] = lcd->lcd_pre_versions[1];
			trd->trd_pre_versions[2] = lcd->lcd_pre_versions[2];
			trd->trd_pre_versions[3] = lcd->lcd_pre_versions[3];
		}
	}
	mutex_unlock(&ted->ted_lcd_lock);

	return found;
}
EXPORT_SYMBOL(req_can_reconstruct);

bool tgt_check_resent(struct ptlrpc_request *req, struct tg_reply_data *trd)
{
	struct lsd_reply_data *lrd;
	bool need_reconstruct = false;

	ENTRY;

	if (likely(!(lustre_msg_get_flags(req->rq_reqmsg) & MSG_RESENT)))
		return false;

	if (req_can_reconstruct(req, trd)) {
		lrd = &trd->trd_reply;
		req->rq_transno = lrd->lrd_transno;
		req->rq_status = lrd->lrd_result;
		if (req->rq_status != 0)
			req->rq_transno = 0;
		lustre_msg_set_transno(req->rq_repmsg, req->rq_transno);
		lustre_msg_set_status(req->rq_repmsg, req->rq_status);

		DEBUG_REQ(D_HA, req, "reconstruct resent RPC");
		need_reconstruct = true;
	} else {
		DEBUG_REQ(D_HA, req, "no reply for RESENT req");
	}

	return need_reconstruct;
}
EXPORT_SYMBOL(tgt_check_resent);
