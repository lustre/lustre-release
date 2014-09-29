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
 * Copyright (c) 2011, 2012, Intel Corporation.
 */
/*
 * lustre/target/tgt_handler.c
 *
 * Lustre Unified Target request handler code
 *
 * Author: Brian Behlendorf <behlendorf1@llnl.gov>
 * Author: Mikhail Pershin <mike.pershin@intel.com>
 */

#define DEBUG_SUBSYSTEM S_CLASS

#include <obd.h>
#include <obd_class.h>

#include "tgt_internal.h"

char *tgt_name(struct lu_target *tgt)
{
	LASSERT(tgt->lut_obd != NULL);
	return tgt->lut_obd->obd_name;
}
EXPORT_SYMBOL(tgt_name);

static int tgt_unpack_req_pack_rep(struct tgt_session_info *tsi, __u32 flags)
{
	struct req_capsule	*pill = tsi->tsi_pill;
	const struct mdt_body	*body = NULL;
	int			 rc = 0;

	ENTRY;

	if (req_capsule_has_field(pill, &RMF_MDT_BODY, RCL_CLIENT)) {
		body = req_capsule_client_get(pill, &RMF_MDT_BODY);
		if (body == NULL)
			RETURN(-EFAULT);
	}

	if (flags & HABEO_REFERO) {
		/* Pack reply */
		if (req_capsule_has_field(pill, &RMF_MDT_MD, RCL_SERVER))
			req_capsule_set_size(pill, &RMF_MDT_MD, RCL_SERVER,
					     body ? body->eadatasize : 0);
		if (req_capsule_has_field(pill, &RMF_LOGCOOKIES, RCL_SERVER))
			req_capsule_set_size(pill, &RMF_LOGCOOKIES,
					     RCL_SERVER, 0);

		rc = req_capsule_server_pack(pill);
	}
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
	__u32	 flags;

	ENTRY;

	LASSERT(h->th_act != NULL);
	LASSERT(h->th_opc == lustre_msg_get_opc(req->rq_reqmsg));
	LASSERT(current->journal_info == NULL);

	rc = 0;
	flags = h->th_flags;
	LASSERT(ergo(flags & (HABEO_CORPUS | HABEO_REFERO),
		     h->th_fmt != NULL));
	if (h->th_fmt != NULL) {
		req_capsule_set(tsi->tsi_pill, h->th_fmt);
		rc = tgt_unpack_req_pack_rep(tsi, flags);
	}

	if (rc == 0 && flags & MUTABOR &&
	    tgt_conn_flags(tsi) & OBD_CONNECT_RDONLY)
		rc = -EROFS;

	if (rc == 0 && flags & HABEO_CLAVIS) {
		struct ldlm_request *dlm_req;

		LASSERT(h->th_fmt != NULL);

		dlm_req = req_capsule_client_get(tsi->tsi_pill, &RMF_DLM_REQ);
		if (dlm_req != NULL) {
			if (unlikely(dlm_req->lock_desc.l_resource.lr_type ==
				     LDLM_IBITS &&
				     dlm_req->lock_desc.l_policy_data.\
				     l_inodebits.bits == 0)) {
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
			DEBUG_REQ(D_ERROR, req, "%s \"handler\" %s did not "
				  "pack reply and returned 0 error\n",
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

	/*
	 * If we're DISCONNECTing, the export_data is already freed
	 *
	 * WAS if (likely(... && h->mh_opc != MDS_DISCONNECT))
	 */
	if (likely(rc == 0 && req->rq_export))
		target_committed_to_req(req);

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
	case MDS_DONE_WRITING:
	case MDS_SYNC: /* used in unmounting */
	case OBD_PING:
	case MDS_REINT:
	case UPDATE_OBJ:
	case SEQ_QUERY:
	case FLD_QUERY:
	case LDLM_ENQUEUE:
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
int tgt_handle_recovery(struct ptlrpc_request *req, int reply_fail_id)
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
	if (req_xid_is_last(req)) {
		if (!(lustre_msg_get_flags(req->rq_reqmsg) &
		      (MSG_RESENT | MSG_REPLAY))) {
			DEBUG_REQ(D_WARNING, req, "rq_xid "LPU64" matches "
				  "last_xid, expected REPLAY or RESENT flag "
				  "(%x)", req->rq_xid,
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
	if (unlikely(req->rq_export->exp_obd->obd_recovering)) {
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

int tgt_request_handle(struct ptlrpc_request *req)
{
	struct tgt_session_info	*tsi = tgt_ses_info(req->rq_svc_thread->t_env);

	struct lustre_msg	*msg = req->rq_reqmsg;
	struct tgt_handler	*h;
	struct tgt_opc_slice	*s;
	struct lu_target	*tgt;
	int			 request_fail_id = 0;
	__u32			 opc = lustre_msg_get_opc(msg);
	int			 rc;

	ENTRY;

	/* Refill(initilize) the context, in case it is
	 * not initialized yet. */
	lu_env_refill(req->rq_svc_thread->t_env);

	req_capsule_init(&req->rq_pill, req, RCL_SERVER);
	tsi->tsi_pill = &req->rq_pill;
	tsi->tsi_env = req->rq_svc_thread->t_env;
	tsi->tsi_dlm_req = NULL;

	/* if request has export then get handlers slice from corresponding
	 * target, otherwise that should be connect operation */
	if (opc == MDS_CONNECT || opc == OST_CONNECT ||
	    opc == MGS_CONNECT) {
		req_capsule_set(&req->rq_pill, &RQF_CONNECT);
		rc = target_handle_connect(req);
		if (rc != 0) {
			rc = ptlrpc_error(req);
			GOTO(out, rc);
		}
	}

	if (unlikely(!class_connected_export(req->rq_export))) {
		CDEBUG(D_HA, "operation %d on unconnected OST from %s\n",
		       opc, libcfs_id2str(req->rq_peer));
		req->rq_status = -ENOTCONN;
		rc = ptlrpc_error(req);
		GOTO(out, rc);
	}

	tsi->tsi_tgt = tgt = class_exp2tgt(req->rq_export);
	tsi->tsi_exp = req->rq_export;

	request_fail_id = tgt->lut_request_fail_id;
	tsi->tsi_reply_fail_id = tgt->lut_reply_fail_id;

	for (s = tgt->lut_slice; s->tos_hs != NULL; s++)
		if (s->tos_opc_start <= opc && opc < s->tos_opc_end)
			break;

	/* opcode was not found in slice */
	if (unlikely(s->tos_hs == NULL)) {
		CERROR("%s: no handlers for opcode 0x%x\n", tgt_name(tgt), opc);
		req->rq_status = -ENOTSUPP;
		rc = ptlrpc_error(req);
		GOTO(out, rc);
	}

	if (CFS_FAIL_CHECK_ORSET(request_fail_id, CFS_FAIL_ONCE))
		GOTO(out, rc = 0);

	LASSERT(current->journal_info == NULL);

	LASSERT(opc >= s->tos_opc_start && opc < s->tos_opc_end);
	h = s->tos_hs + (opc - s->tos_opc_start);
	if (unlikely(h->th_opc == 0)) {
		CERROR("%s: unsupported opcode 0x%x\n", tgt_name(tgt), opc);
		req->rq_status = -ENOTSUPP;
		rc = ptlrpc_error(req);
		GOTO(out, rc);
	}

	rc = lustre_msg_check_version(msg, h->th_version);
	if (unlikely(rc)) {
		DEBUG_REQ(D_ERROR, req, "%s: drop mal-formed request, version"
			  " %08x, expecting %08x\n", tgt_name(tgt),
			  lustre_msg_get_version(msg), h->th_version);
		req->rq_status = -EINVAL;
		rc = ptlrpc_error(req);
		GOTO(out, rc);
	}

	rc = tgt_handle_recovery(req, tsi->tsi_reply_fail_id);
	if (likely(rc == 1)) {
		LASSERTF(h->th_opc == opc, "opcode mismatch %d != %d\n",
			 h->th_opc, opc);
		rc = tgt_handle_request0(tsi, h, req);
		if (rc)
			GOTO(out, rc);
	}
	EXIT;
out:
	req_capsule_fini(tsi->tsi_pill);
	tsi->tsi_pill = NULL;
	return rc;
}
EXPORT_SYMBOL(tgt_request_handle);

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

/*
 * Security functions
 */
static inline void tgt_init_sec_none(struct obd_connect_data *reply)
{
	reply->ocd_connect_flags &= ~(OBD_CONNECT_RMT_CLIENT |
				      OBD_CONNECT_RMT_CLIENT_FORCE |
				      OBD_CONNECT_MDS_CAPA |
				      OBD_CONNECT_OSS_CAPA);
}

static int tgt_init_sec_level(struct ptlrpc_request *req)
{
	struct lu_target	*tgt = class_exp2tgt(req->rq_export);
	char			*client = libcfs_nid2str(req->rq_peer.nid);
	struct obd_connect_data	*data, *reply;
	int			 rc = 0;
	bool			 remote;

	ENTRY;

	data = req_capsule_client_get(&req->rq_pill, &RMF_CONNECT_DATA);
	reply = req_capsule_server_get(&req->rq_pill, &RMF_CONNECT_DATA);
	if (data == NULL || reply == NULL)
		RETURN(-EFAULT);

	/* connection from MDT is always trusted */
	if (req->rq_auth_usr_mdt) {
		tgt_init_sec_none(reply);
		RETURN(0);
	}

	/* no GSS support case */
	if (!req->rq_auth_gss) {
		if (tgt->lut_sec_level > LUSTRE_SEC_NONE) {
			CWARN("client %s -> target %s does not use GSS, "
			      "can not run under security level %d.\n",
			      client, tgt_name(tgt), tgt->lut_sec_level);
			RETURN(-EACCES);
		} else {
			tgt_init_sec_none(reply);
			RETURN(0);
		}
	}

	/* old version case */
	if (unlikely(!(data->ocd_connect_flags & OBD_CONNECT_RMT_CLIENT) ||
		     !(data->ocd_connect_flags & OBD_CONNECT_MDS_CAPA) ||
		     !(data->ocd_connect_flags & OBD_CONNECT_OSS_CAPA))) {
		if (tgt->lut_sec_level > LUSTRE_SEC_NONE) {
			CWARN("client %s -> target %s uses old version, "
			      "can not run under security level %d.\n",
			      client, tgt_name(tgt), tgt->lut_sec_level);
			RETURN(-EACCES);
		} else {
			CWARN("client %s -> target %s uses old version, "
			      "run under security level %d.\n",
			      client, tgt_name(tgt), tgt->lut_sec_level);
			tgt_init_sec_none(reply);
			RETURN(0);
		}
	}

	remote = data->ocd_connect_flags & OBD_CONNECT_RMT_CLIENT_FORCE;
	if (remote) {
		if (!req->rq_auth_remote)
			CDEBUG(D_SEC, "client (local realm) %s -> target %s "
			       "asked to be remote.\n", client, tgt_name(tgt));
	} else if (req->rq_auth_remote) {
		remote = true;
		CDEBUG(D_SEC, "client (remote realm) %s -> target %s is set "
		       "as remote by default.\n", client, tgt_name(tgt));
	}

	if (remote) {
		if (!tgt->lut_oss_capa) {
			CDEBUG(D_SEC,
			       "client %s -> target %s is set as remote,"
			       " but OSS capabilities are not enabled: %d.\n",
			       client, tgt_name(tgt), tgt->lut_oss_capa);
			RETURN(-EACCES);
		}
	} else {
		if (req->rq_auth_uid == INVALID_UID) {
			CDEBUG(D_SEC, "client %s -> target %s: user is not "
			       "authenticated!\n", client, tgt_name(tgt));
			RETURN(-EACCES);
		}
	}


	switch (tgt->lut_sec_level) {
	case LUSTRE_SEC_NONE:
		if (remote) {
			CDEBUG(D_SEC,
			       "client %s -> target %s is set as remote, "
			       "can not run under security level %d.\n",
			       client, tgt_name(tgt), tgt->lut_sec_level);
			RETURN(-EACCES);
		}
		tgt_init_sec_none(reply);
		break;
	case LUSTRE_SEC_REMOTE:
		if (!remote)
			tgt_init_sec_none(reply);
		break;
	case LUSTRE_SEC_ALL:
		if (remote)
			break;
		reply->ocd_connect_flags &= ~(OBD_CONNECT_RMT_CLIENT |
					      OBD_CONNECT_RMT_CLIENT_FORCE);
		if (!tgt->lut_oss_capa)
			reply->ocd_connect_flags &= ~OBD_CONNECT_OSS_CAPA;
		if (!tgt->lut_mds_capa)
			reply->ocd_connect_flags &= ~OBD_CONNECT_MDS_CAPA;
		break;
	default:
		RETURN(-EINVAL);
	}

	RETURN(rc);
}

int tgt_connect_check_sptlrpc(struct ptlrpc_request *req, struct obd_export *exp)
{
	struct lu_target	*tgt = class_exp2tgt(exp);
	struct sptlrpc_flavor	 flvr;
	int			 rc = 0;

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
					     req->rq_peer.nid,
					     &flvr);
		read_unlock(&tgt->lut_sptlrpc_lock);

		spin_lock(&exp->exp_lock);
		exp->exp_sp_peer = req->rq_sp_from;
		exp->exp_flvr = flvr;
		if (exp->exp_flvr.sf_rpc != SPTLRPC_FLVR_ANY &&
		    exp->exp_flvr.sf_rpc != req->rq_flvr.sf_rpc) {
			CERROR("%s: unauthorized rpc flavor %x from %s, "
			       "expect %x\n", tgt_name(tgt),
			       req->rq_flvr.sf_rpc,
			       libcfs_nid2str(req->rq_peer.nid),
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

int tgt_connect(struct tgt_session_info *tsi)
{
	struct ptlrpc_request	*req = tgt_ses_req(tsi);
	struct obd_connect_data	*reply;
	int			 rc;

	ENTRY;

	rc = tgt_init_sec_level(req);
	if (rc != 0)
		GOTO(out, rc);

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
	spin_unlock(&tsi->tsi_exp->exp_lock);

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

	rc = target_handle_ping(tgt_ses_req(tsi));
	if (rc)
		RETURN(err_serious(rc));

	RETURN(rc);
}
EXPORT_SYMBOL(tgt_obd_ping);

int tgt_obd_log_cancel(struct tgt_session_info *tsi)
{
	return err_serious(-EOPNOTSUPP);
}
EXPORT_SYMBOL(tgt_obd_log_cancel);

int tgt_obd_qc_callback(struct tgt_session_info *tsi)
{
	return err_serious(-EOPNOTSUPP);
}
EXPORT_SYMBOL(tgt_obd_qc_callback);

static int tgt_sendpage(struct tgt_session_info *tsi, struct lu_rdpg *rdpg,
			int nob)
{
	struct tgt_thread_info	*tti = tgt_th_info(tsi->tsi_env);
	struct ptlrpc_request	*req = tgt_ses_req(tsi);
	struct obd_export	*exp = req->rq_export;
	struct ptlrpc_bulk_desc	*desc;
	struct l_wait_info	*lwi = &tti->tti_u.rdpg.tti_wait_info;
	int			 tmpcount;
	int			 tmpsize;
	int			 i;
	int			 rc;

	ENTRY;

	desc = ptlrpc_prep_bulk_exp(req, rdpg->rp_npages, 1, BULK_PUT_SOURCE,
				    MDS_BULK_PORTAL);
	if (desc == NULL)
		RETURN(-ENOMEM);

	if (!(exp_connect_flags(exp) & OBD_CONNECT_BRW_SIZE))
		/* old client requires reply size in it's PAGE_CACHE_SIZE,
		 * which is rdpg->rp_count */
		nob = rdpg->rp_count;

	for (i = 0, tmpcount = nob; i < rdpg->rp_npages && tmpcount > 0;
	     i++, tmpcount -= tmpsize) {
		tmpsize = min_t(int, tmpcount, PAGE_CACHE_SIZE);
		ptlrpc_prep_bulk_page_pin(desc, rdpg->rp_pages[i], 0, tmpsize);
	}

	LASSERT(desc->bd_nob == nob);
	rc = target_bulk_io(exp, desc, lwi);
	ptlrpc_free_bulk_pin(desc);
	RETURN(rc);
}
EXPORT_SYMBOL(tgt_sendpage);

/*
 * OBD_IDX_READ handler
 */
int tgt_obd_idx_read(struct tgt_session_info *tsi)
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
	rdpg->rp_npages = (rdpg->rp_count + PAGE_CACHE_SIZE -1) >> PAGE_CACHE_SHIFT;

	/* allocate pages to store the containers */
	OBD_ALLOC(rdpg->rp_pages, rdpg->rp_npages * sizeof(rdpg->rp_pages[0]));
	if (rdpg->rp_pages == NULL)
		GOTO(out, rc = -ENOMEM);
	for (i = 0; i < rdpg->rp_npages; i++) {
		rdpg->rp_pages[i] = alloc_page(GFP_IOFS);
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
		OBD_FREE(rdpg->rp_pages,
			 rdpg->rp_npages * sizeof(rdpg->rp_pages[0]));
	}
	return rc;
}
EXPORT_SYMBOL(tgt_obd_idx_read);

struct tgt_handler tgt_obd_handlers[] = {
TGT_OBD_HDL    (0,	OBD_PING,		tgt_obd_ping),
TGT_OBD_HDL_VAR(0,	OBD_LOG_CANCEL,		tgt_obd_log_cancel),
TGT_OBD_HDL_VAR(0,	OBD_QC_CALLBACK,	tgt_obd_qc_callback),
TGT_OBD_HDL    (0,	OBD_IDX_READ,		tgt_obd_idx_read)
};
EXPORT_SYMBOL(tgt_obd_handlers);

/*
 * Unified target DLM handlers.
 */
struct ldlm_callback_suite tgt_dlm_cbs = {
	.lcs_completion	= ldlm_server_completion_ast,
	.lcs_blocking	= ldlm_server_blocking_ast,
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

	rc = ldlm_handle_enqueue0(tsi->tsi_exp->exp_obd->obd_namespace, req,
				  tsi->tsi_dlm_req, &tgt_dlm_cbs);
	if (rc)
		RETURN(err_serious(rc));

	tsi->tsi_reply_fail_id = OBD_FAIL_LDLM_REPLY;
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
EXPORT_SYMBOL(tgt_convert);

int tgt_bl_callback(struct tgt_session_info *tsi)
{
	return err_serious(-EOPNOTSUPP);
}
EXPORT_SYMBOL(tgt_bl_callback);

int tgt_cp_callback(struct tgt_session_info *tsi)
{
	return err_serious(-EOPNOTSUPP);
}
EXPORT_SYMBOL(tgt_cp_callback);

/* generic LDLM target handler */
struct tgt_handler tgt_dlm_handlers[] = {
TGT_DLM_HDL    (HABEO_CLAVIS,	LDLM_ENQUEUE,		tgt_enqueue),
TGT_DLM_HDL_VAR(HABEO_CLAVIS,	LDLM_CONVERT,		tgt_convert),
TGT_DLM_HDL_VAR(0,		LDLM_BL_CALLBACK,	tgt_bl_callback),
TGT_DLM_HDL_VAR(0,		LDLM_CP_CALLBACK,	tgt_cp_callback)
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

int tgt_llog_close(struct tgt_session_info *tsi)
{
	int rc;

	ENTRY;

	rc = llog_origin_handle_close(tgt_ses_req(tsi));

	RETURN(rc);
}
EXPORT_SYMBOL(tgt_llog_close);


int tgt_llog_destroy(struct tgt_session_info *tsi)
{
	int rc;

	ENTRY;

	rc = llog_origin_handle_destroy(tgt_ses_req(tsi));

	RETURN(rc);
}
EXPORT_SYMBOL(tgt_llog_destroy);

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
TGT_LLOG_HDL    (0,	LLOG_ORIGIN_HANDLE_DESTROY,	tgt_llog_destroy),
TGT_LLOG_HDL_VAR(0,	LLOG_ORIGIN_HANDLE_CLOSE,	tgt_llog_close),
};
EXPORT_SYMBOL(tgt_llog_handlers);

/*
 * sec context handlers
 */
/* XXX: Implement based on mdt_sec_ctx_handle()? */
int tgt_sec_ctx_handle(struct tgt_session_info *tsi)
{
	return 0;
}

struct tgt_handler tgt_sec_ctx_handlers[] = {
TGT_SEC_HDL_VAR(0,	SEC_CTX_INIT,		tgt_sec_ctx_handle),
TGT_SEC_HDL_VAR(0,	SEC_CTX_INIT_CONT,	tgt_sec_ctx_handle),
TGT_SEC_HDL_VAR(0,	SEC_CTX_FINI,		tgt_sec_ctx_handle),
};
EXPORT_SYMBOL(tgt_sec_ctx_handlers);
