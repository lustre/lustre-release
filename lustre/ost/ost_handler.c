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
 * version 2 along with this program; If not, see
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2001, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2013, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/ost/ost_handler.c
 *
 * Author: Peter J. Braam <braam@clusterfs.com>
 * Author: Phil Schwan <phil@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_OST

#include <linux/module.h>
#include <obd_cksum.h>
#include <obd_ost.h>
#include <lustre_net.h>
#include <lustre_dlm.h>
#include <lustre_export.h>
#include <lustre_debug.h>
#include <lustre_fid.h>
#include <lustre_fld.h>
#include <linux/init.h>
#include <lprocfs_status.h>
#include <libcfs/list.h>
#include <lustre_quota.h>
#include <lustre_fid.h>
#include "ost_internal.h"
#include <lustre_fid.h>

static int oss_num_threads;
CFS_MODULE_PARM(oss_num_threads, "i", int, 0444,
                "number of OSS service threads to start");

static int ost_num_threads;
CFS_MODULE_PARM(ost_num_threads, "i", int, 0444,
                "number of OST service threads to start (deprecated)");

static int oss_num_create_threads;
CFS_MODULE_PARM(oss_num_create_threads, "i", int, 0444,
                "number of OSS create threads to start");

static char *oss_cpts;
CFS_MODULE_PARM(oss_cpts, "s", charp, 0444,
		"CPU partitions OSS threads should run on");

static char *oss_io_cpts;
CFS_MODULE_PARM(oss_io_cpts, "s", charp, 0444,
		"CPU partitions OSS IO threads should run on");

/*
 * this page is allocated statically when module is initializing
 * it is used to simulate data corruptions, see ost_checksum_bulk()
 * for details. as the original pages provided by the layers below
 * can be remain in the internal cache, we do not want to modify
 * them.
 */
static struct page *ost_page_to_corrupt = NULL;

/**
 * Do not return server-side uid/gid to remote client
 */
static void ost_drop_id(struct obd_export *exp, struct obdo *oa)
{
        if (exp_connect_rmtclient(exp)) {
                oa->o_uid = -1;
                oa->o_gid = -1;
                oa->o_valid &= ~(OBD_MD_FLUID | OBD_MD_FLGID);
        }
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
static int ost_validate_obdo(struct obd_export *exp, struct obdo *oa,
			     struct obd_ioobj *ioobj)
{
	int rc = 0;

	if (unlikely(!(exp_connect_flags(exp) & OBD_CONNECT_FID) &&
		     fid_seq_is_echo(oa->o_oi.oi.oi_seq) && oa != NULL)) {
		/* Sigh 2.[123] client still sends echo req with oi_id = 0
		 * during create, and we will reset this to 1, since this
		 * oi_id is basically useless in the following create process,
		 * but oi_id == 0 will make it difficult to tell whether it is
		 * real FID or ost_id. */
		oa->o_oi.oi_fid.f_oid = oa->o_oi.oi.oi_id ?: 1;
		oa->o_oi.oi_fid.f_seq = FID_SEQ_ECHO;
		oa->o_oi.oi_fid.f_ver = 0;
	} else {
		if (unlikely((oa == NULL) || ostid_id(&oa->o_oi) == 0))
			GOTO(out, rc = -EPROTO);

		/* Note: this check might be forced in 2.5 or 2.6, i.e.
		 * all of the requests are required to setup FLGROUP */
		if (unlikely(!(oa->o_valid & OBD_MD_FLGROUP))) {
			ostid_set_seq_mdt0(&oa->o_oi);
			if (ioobj)
				ostid_set_seq_mdt0(&ioobj->ioo_oid);
			oa->o_valid |= OBD_MD_FLGROUP;
		}

		if (unlikely(!(fid_seq_is_idif(ostid_seq(&oa->o_oi)) ||
			       fid_seq_is_mdt0(ostid_seq(&oa->o_oi)) ||
			       fid_seq_is_norm(ostid_seq(&oa->o_oi)) ||
			       fid_seq_is_echo(ostid_seq(&oa->o_oi)))))
			GOTO(out, rc = -EPROTO);
	}

	if (ioobj != NULL) {
		unsigned max_brw = ioobj_max_brw_get(ioobj);

		if (unlikely((max_brw & (max_brw - 1)) != 0)) {
			CERROR("%s: client %s sent bad ioobj max %u for "DOSTID
			       ": rc = -EPROTO\n", exp->exp_obd->obd_name,
			       obd_export_nid2str(exp), max_brw,
			       POSTID(&oa->o_oi));
			GOTO(out, rc = -EPROTO);
		}
		ioobj->ioo_oid = oa->o_oi;
	}

out:
	if (rc != 0)
		CERROR("%s: client %s sent bad object "DOSTID": rc = %d\n",
		       exp->exp_obd->obd_name, obd_export_nid2str(exp),
		       oa ? ostid_seq(&oa->o_oi) : -1,
		       oa ? ostid_id(&oa->o_oi) : -1, rc);
	return rc;
}

void oti_to_request(struct obd_trans_info *oti, struct ptlrpc_request *req)
{
        struct oti_req_ack_lock *ack_lock;
        int i;

        if (oti == NULL)
                return;

        if (req->rq_repmsg) {
                __u64 versions[PTLRPC_NUM_VERSIONS] = { 0 };
                lustre_msg_set_transno(req->rq_repmsg, oti->oti_transno);
                versions[0] = oti->oti_pre_version;
                lustre_msg_set_versions(req->rq_repmsg, versions);
        }
        req->rq_transno = oti->oti_transno;

        /* XXX 4 == entries in oti_ack_locks??? */
        for (ack_lock = oti->oti_ack_locks, i = 0; i < 4; i++, ack_lock++) {
                if (!ack_lock->mode)
                        break;
                /* XXX not even calling target_send_reply in some cases... */
                ptlrpc_save_lock (req, &ack_lock->lock, ack_lock->mode, 0);
        }
}

static int ost_destroy(struct obd_export *exp, struct ptlrpc_request *req,
                       struct obd_trans_info *oti)
{
        struct ost_body *body, *repbody;
        struct lustre_capa *capa = NULL;
        int rc;
        ENTRY;

        /* Get the request body */
        body = req_capsule_client_get(&req->rq_pill, &RMF_OST_BODY);
        if (body == NULL)
                RETURN(-EFAULT);

	if (ostid_id(&body->oa.o_oi) == 0)
		RETURN(-EPROTO);

        rc = ost_validate_obdo(exp, &body->oa, NULL);
        if (rc)
                RETURN(rc);

        /* If there's a DLM request, cancel the locks mentioned in it*/
        if (req_capsule_field_present(&req->rq_pill, &RMF_DLM_REQ, RCL_CLIENT)) {
                struct ldlm_request *dlm;

                dlm = req_capsule_client_get(&req->rq_pill, &RMF_DLM_REQ);
                if (dlm == NULL)
                        RETURN (-EFAULT);
                ldlm_request_cancel(req, dlm, 0);
        }

        /* If there's a capability, get it */
        if (body->oa.o_valid & OBD_MD_FLOSSCAPA) {
                capa = req_capsule_client_get(&req->rq_pill, &RMF_CAPA1);
                if (capa == NULL) {
                        CERROR("Missing capability for OST DESTROY");
                        RETURN (-EFAULT);
                }
        }

        /* Prepare the reply */
        rc = req_capsule_server_pack(&req->rq_pill);
        if (rc)
                RETURN(rc);

        /* Get the log cancellation cookie */
        if (body->oa.o_valid & OBD_MD_FLCOOKIE)
                oti->oti_logcookies = &body->oa.o_lcookie;

        /* Finish the reply */
        repbody = req_capsule_server_get(&req->rq_pill, &RMF_OST_BODY);
        memcpy(&repbody->oa, &body->oa, sizeof(body->oa));

        /* Do the destroy and set the reply status accordingly  */
        req->rq_status = obd_destroy(req->rq_svc_thread->t_env, exp,
                                     &repbody->oa, NULL, oti, NULL, capa);
        RETURN(0);
}

/**
 * Helper function for getting server side [start, start+count] DLM lock
 * if asked by client.
 */
static int ost_lock_get(struct obd_export *exp, struct obdo *oa,
                        __u64 start, __u64 count, struct lustre_handle *lh,
			int mode, __u64 flags)
{
        struct ldlm_res_id res_id;
        ldlm_policy_data_t policy;
        __u64 end = start + count;

        ENTRY;

        LASSERT(!lustre_handle_is_used(lh));
        /* o_id and o_gr are used for localizing resource, if client miss to set
         * them, do not trigger ASSERTION. */
        if (unlikely((oa->o_valid & (OBD_MD_FLID | OBD_MD_FLGROUP)) !=
                     (OBD_MD_FLID | OBD_MD_FLGROUP)))
                RETURN(-EPROTO);

        if (!(oa->o_valid & OBD_MD_FLFLAGS) ||
            !(oa->o_flags & OBD_FL_SRVLOCK))
                RETURN(0);

	if (mode == LCK_MINMODE)
		RETURN(0);

	ostid_build_res_name(&oa->o_oi, &res_id);
        CDEBUG(D_INODE, "OST-side extent lock.\n");

        policy.l_extent.start = start & CFS_PAGE_MASK;

        /* If ->o_blocks is EOF it means "lock till the end of the
         * file". Otherwise, it's size of a hole being punched (in bytes) */
        if (count == OBD_OBJECT_EOF || end < start)
                policy.l_extent.end = OBD_OBJECT_EOF;
        else
                policy.l_extent.end = end | ~CFS_PAGE_MASK;

        RETURN(ldlm_cli_enqueue_local(exp->exp_obd->obd_namespace, &res_id,
                                      LDLM_EXTENT, &policy, mode, &flags,
                                      ldlm_blocking_ast, ldlm_completion_ast,
				      ldlm_glimpse_ast, NULL, 0, LVB_T_NONE,
				      NULL, lh));
}

/* Helper function: release lock, if any. */
static void ost_lock_put(struct obd_export *exp,
                         struct lustre_handle *lh, int mode)
{
        ENTRY;
        if (lustre_handle_is_used(lh))
                ldlm_lock_decref(lh, mode);
        EXIT;
}

static int ost_getattr(struct obd_export *exp, struct ptlrpc_request *req)
{
        struct ost_body *body, *repbody;
        struct obd_info *oinfo;
        struct lustre_handle lh = { 0 };
        struct lustre_capa *capa = NULL;
	ldlm_mode_t lock_mode;
        int rc;
        ENTRY;

        body = req_capsule_client_get(&req->rq_pill, &RMF_OST_BODY);
        if (body == NULL)
                RETURN(-EFAULT);

        rc = ost_validate_obdo(exp, &body->oa, NULL);
        if (rc)
                RETURN(rc);

        if (body->oa.o_valid & OBD_MD_FLOSSCAPA) {
                capa = req_capsule_client_get(&req->rq_pill, &RMF_CAPA1);
                if (capa == NULL) {
                        CERROR("Missing capability for OST GETATTR");
                        RETURN(-EFAULT);
                }
        }

        rc = req_capsule_server_pack(&req->rq_pill);
        if (rc)
                RETURN(rc);

        repbody = req_capsule_server_get(&req->rq_pill, &RMF_OST_BODY);
        repbody->oa = body->oa;

	lock_mode = LCK_MINMODE;
	if (body->oa.o_valid & OBD_MD_FLFLAGS &&
	    body->oa.o_flags & OBD_FL_SRVLOCK) {
		lock_mode = LCK_PR;
		if (body->oa.o_flags & OBD_FL_FLUSH)
			lock_mode = LCK_PW;
	}
	rc = ost_lock_get(exp, &repbody->oa, 0, OBD_OBJECT_EOF, &lh,
			  lock_mode, 0);
	if (rc)
		RETURN(rc);

        OBD_ALLOC_PTR(oinfo);
        if (!oinfo)
                GOTO(unlock, rc = -ENOMEM);
        oinfo->oi_oa = &repbody->oa;
        oinfo->oi_capa = capa;

        req->rq_status = obd_getattr(req->rq_svc_thread->t_env, exp, oinfo);

        OBD_FREE_PTR(oinfo);

        ost_drop_id(exp, &repbody->oa);

	if (!(repbody->oa.o_valid & OBD_MD_FLFLAGS)) {
		repbody->oa.o_valid |= OBD_MD_FLFLAGS;
		repbody->oa.o_flags = 0;
	}
	repbody->oa.o_flags |= OBD_FL_FLUSH;

unlock:
	ost_lock_put(exp, &lh, lock_mode);
	RETURN(rc);
}

static int ost_statfs(struct ptlrpc_request *req)
{
        struct obd_statfs *osfs;
        int rc;
        ENTRY;

        rc = req_capsule_server_pack(&req->rq_pill);
        if (rc)
                RETURN(rc);

        osfs = req_capsule_server_get(&req->rq_pill, &RMF_OBD_STATFS);

        req->rq_status = obd_statfs(req->rq_svc_thread->t_env, req->rq_export,
                                    osfs,
                                    cfs_time_shift_64(-OBD_STATFS_CACHE_SECONDS),
                                    0);
        if (req->rq_status != 0)
                CERROR("ost: statfs failed: rc %d\n", req->rq_status);

	if (OBD_FAIL_CHECK(OBD_FAIL_OST_STATFS_EINPROGRESS))
		req->rq_status = -EINPROGRESS;

        RETURN(0);
}

static int ost_create(struct obd_export *exp, struct ptlrpc_request *req,
                      struct obd_trans_info *oti)
{
        struct ost_body *body, *repbody;
        int rc;
        ENTRY;

        body = req_capsule_client_get(&req->rq_pill, &RMF_OST_BODY);
        if (body == NULL)
                RETURN(-EFAULT);

        rc = ost_validate_obdo(req->rq_export, &body->oa, NULL);
        if (rc)
                RETURN(rc);

        rc = req_capsule_server_pack(&req->rq_pill);
        if (rc)
                RETURN(rc);

        repbody = req_capsule_server_get(&req->rq_pill, &RMF_OST_BODY);
        repbody->oa = body->oa;
        oti->oti_logcookies = &body->oa.o_lcookie;

        req->rq_status = obd_create(req->rq_svc_thread->t_env, exp,
                                    &repbody->oa, NULL, oti);
        //obd_log_cancel(conn, NULL, 1, oti->oti_logcookies, 0);
        RETURN(0);
}

static int ost_punch(struct obd_export *exp, struct ptlrpc_request *req,
                     struct obd_trans_info *oti)
{
        struct ost_body *body, *repbody;
	__u64 flags = 0;
        struct lustre_handle lh = {0,};
	int rc;
        ENTRY;

        /* check that we do support OBD_CONNECT_TRUNCLOCK. */
        CLASSERT(OST_CONNECT_SUPPORTED & OBD_CONNECT_TRUNCLOCK);

        body = req_capsule_client_get(&req->rq_pill, &RMF_OST_BODY);
        if (body == NULL)
                RETURN(-EFAULT);

        rc = ost_validate_obdo(exp, &body->oa, NULL);
        if (rc)
                RETURN(rc);

        if ((body->oa.o_valid & (OBD_MD_FLSIZE | OBD_MD_FLBLOCKS)) !=
            (OBD_MD_FLSIZE | OBD_MD_FLBLOCKS))
                RETURN(-EPROTO);

        rc = req_capsule_server_pack(&req->rq_pill);
        if (rc)
                RETURN(rc);

        /* standard truncate optimization: if file body is completely
         * destroyed, don't send data back to the server. */
        if (body->oa.o_size == 0)
		flags |= LDLM_FL_AST_DISCARD_DATA;

        repbody = req_capsule_server_get(&req->rq_pill, &RMF_OST_BODY);
        repbody->oa = body->oa;

        rc = ost_lock_get(exp, &repbody->oa, repbody->oa.o_size,
                          repbody->oa.o_blocks, &lh, LCK_PW, flags);
        if (rc == 0) {
                struct obd_info *oinfo;
                struct lustre_capa *capa = NULL;

                if (repbody->oa.o_valid & OBD_MD_FLFLAGS &&
                    repbody->oa.o_flags == OBD_FL_SRVLOCK)
                        /*
                         * If OBD_FL_SRVLOCK is the only bit set in
                         * ->o_flags, clear OBD_MD_FLFLAGS to avoid falling
                         * through filter_setattr() to filter_iocontrol().
                         */
                        repbody->oa.o_valid &= ~OBD_MD_FLFLAGS;

                if (repbody->oa.o_valid & OBD_MD_FLOSSCAPA) {
                        capa = req_capsule_client_get(&req->rq_pill,
                                                      &RMF_CAPA1);
                        if (capa == NULL) {
                                CERROR("Missing capability for OST PUNCH");
                                GOTO(unlock, rc = -EFAULT);
                        }
                }

                OBD_ALLOC_PTR(oinfo);
                if (!oinfo)
                        GOTO(unlock, rc = -ENOMEM);
                oinfo->oi_oa = &repbody->oa;
                oinfo->oi_policy.l_extent.start = oinfo->oi_oa->o_size;
                oinfo->oi_policy.l_extent.end = oinfo->oi_oa->o_blocks;
                oinfo->oi_capa = capa;
                oinfo->oi_flags = OBD_FL_PUNCH;

                req->rq_status = obd_punch(req->rq_svc_thread->t_env, exp,
                                           oinfo, oti, NULL);
                OBD_FREE_PTR(oinfo);
unlock:
                ost_lock_put(exp, &lh, LCK_PW);
        }

        ost_drop_id(exp, &repbody->oa);
        RETURN(rc);
}

static int ost_sync(struct obd_export *exp, struct ptlrpc_request *req,
		    struct obd_trans_info *oti)
{
        struct ost_body *body, *repbody;
        struct obd_info *oinfo;
        struct lustre_capa *capa = NULL;
        int rc;
        ENTRY;

        body = req_capsule_client_get(&req->rq_pill, &RMF_OST_BODY);
        if (body == NULL)
                RETURN(-EFAULT);

        rc = ost_validate_obdo(exp, &body->oa, NULL);
        if (rc)
                RETURN(rc);

        if (body->oa.o_valid & OBD_MD_FLOSSCAPA) {
                capa = req_capsule_client_get(&req->rq_pill, &RMF_CAPA1);
                if (capa == NULL) {
                        CERROR("Missing capability for OST SYNC");
                        RETURN (-EFAULT);
                }
        }

        rc = req_capsule_server_pack(&req->rq_pill);
        if (rc)
                RETURN(rc);

        repbody = req_capsule_server_get(&req->rq_pill, &RMF_OST_BODY);
        repbody->oa = body->oa;

        OBD_ALLOC_PTR(oinfo);
        if (!oinfo)
                RETURN(-ENOMEM);

        oinfo->oi_oa = &repbody->oa;
        oinfo->oi_capa = capa;
	oinfo->oi_jobid = oti->oti_jobid;
        req->rq_status = obd_sync(req->rq_svc_thread->t_env, exp, oinfo,
                                  repbody->oa.o_size, repbody->oa.o_blocks,
                                  NULL);
        OBD_FREE_PTR(oinfo);

        ost_drop_id(exp, &repbody->oa);
        RETURN(0);
}

static int ost_setattr(struct obd_export *exp, struct ptlrpc_request *req,
                       struct obd_trans_info *oti)
{
        struct ost_body *body, *repbody;
        struct obd_info *oinfo;
        struct lustre_capa *capa = NULL;
        int rc;
        ENTRY;

        body = req_capsule_client_get(&req->rq_pill, &RMF_OST_BODY);
        if (body == NULL)
                RETURN(-EFAULT);

        rc = ost_validate_obdo(req->rq_export, &body->oa, NULL);
        if (rc)
                RETURN(rc);

        rc = req_capsule_server_pack(&req->rq_pill);
        if (rc)
                RETURN(rc);

        if (body->oa.o_valid & OBD_MD_FLOSSCAPA) {
                capa = req_capsule_client_get(&req->rq_pill, &RMF_CAPA1);
                if (capa == NULL) {
                        CERROR("Missing capability for OST SETATTR");
                        RETURN (-EFAULT);
                }
        }

        repbody = req_capsule_server_get(&req->rq_pill, &RMF_OST_BODY);
        repbody->oa = body->oa;

        OBD_ALLOC_PTR(oinfo);
        if (!oinfo)
                RETURN(-ENOMEM);
        oinfo->oi_oa = &repbody->oa;
        oinfo->oi_capa = capa;

        req->rq_status = obd_setattr(req->rq_svc_thread->t_env, exp, oinfo,
                                     oti);

        OBD_FREE_PTR(oinfo);

        ost_drop_id(exp, &repbody->oa);
        RETURN(0);
}

static __u32 ost_checksum_bulk(struct ptlrpc_bulk_desc *desc, int opc,
			       cksum_type_t cksum_type)
{
	struct cfs_crypto_hash_desc	*hdesc;
	unsigned int			bufsize;
	int				i, err;
	unsigned char			cfs_alg = cksum_obd2cfs(cksum_type);
	__u32				cksum;

	hdesc = cfs_crypto_hash_init(cfs_alg, NULL, 0);
	if (IS_ERR(hdesc)) {
		CERROR("Unable to initialize checksum hash %s\n",
		       cfs_crypto_hash_name(cfs_alg));
		return PTR_ERR(hdesc);
	}
	CDEBUG(D_INFO, "Checksum for algo %s\n", cfs_crypto_hash_name(cfs_alg));
	for (i = 0; i < desc->bd_iov_count; i++) {

		/* corrupt the data before we compute the checksum, to
		 * simulate a client->OST data error */
		if (i == 0 && opc == OST_WRITE &&
		    OBD_FAIL_CHECK(OBD_FAIL_OST_CHECKSUM_RECEIVE)) {
			int off = desc->bd_iov[i].kiov_offset & ~CFS_PAGE_MASK;
			int len = desc->bd_iov[i].kiov_len;
			struct page *np = ost_page_to_corrupt;
			char *ptr = kmap(desc->bd_iov[i].kiov_page) + off;

			if (np) {
				char *ptr2 = kmap(np) + off;

				memcpy(ptr2, ptr, len);
				memcpy(ptr2, "bad3", min(4, len));
				kunmap(np);
				desc->bd_iov[i].kiov_page = np;
			} else {
				CERROR("can't alloc page for corruption\n");
			}
		}
		cfs_crypto_hash_update_page(hdesc, desc->bd_iov[i].kiov_page,
				  desc->bd_iov[i].kiov_offset & ~CFS_PAGE_MASK,
				  desc->bd_iov[i].kiov_len);

		 /* corrupt the data after we compute the checksum, to
		 * simulate an OST->client data error */
		if (i == 0 && opc == OST_READ &&
		    OBD_FAIL_CHECK(OBD_FAIL_OST_CHECKSUM_SEND)) {
			int off = desc->bd_iov[i].kiov_offset & ~CFS_PAGE_MASK;
			int len = desc->bd_iov[i].kiov_len;
			struct page *np = ost_page_to_corrupt;
			char *ptr = kmap(desc->bd_iov[i].kiov_page) + off;

			if (np) {
				char *ptr2 = kmap(np) + off;

				memcpy(ptr2, ptr, len);
				memcpy(ptr2, "bad4", min(4, len));
				kunmap(np);
				desc->bd_iov[i].kiov_page = np;
			} else {
				CERROR("can't alloc page for corruption\n");
			}
		}
	}

	bufsize = 4;
	err = cfs_crypto_hash_final(hdesc, (unsigned char *)&cksum, &bufsize);
	if (err)
		cfs_crypto_hash_final(hdesc, NULL, NULL);

	return cksum;
}

static int ost_brw_lock_get(int mode, struct obd_export *exp,
                            struct obd_ioobj *obj, struct niobuf_remote *nb,
                            struct lustre_handle *lh)
{
	__u64 flags               = 0;
        int nrbufs                = obj->ioo_bufcnt;
        struct ldlm_res_id res_id;
        ldlm_policy_data_t policy;
        int i;
        ENTRY;

	ostid_build_res_name(&obj->ioo_oid, &res_id);
        LASSERT(mode == LCK_PR || mode == LCK_PW);
        LASSERT(!lustre_handle_is_used(lh));

        if (nrbufs == 0 || !(nb[0].flags & OBD_BRW_SRVLOCK))
                RETURN(0);

        for (i = 1; i < nrbufs; i ++)
                if ((nb[0].flags & OBD_BRW_SRVLOCK) !=
                    (nb[i].flags & OBD_BRW_SRVLOCK))
                        RETURN(-EFAULT);

        policy.l_extent.start = nb[0].offset & CFS_PAGE_MASK;
        policy.l_extent.end   = (nb[nrbufs - 1].offset +
                                 nb[nrbufs - 1].len - 1) | ~CFS_PAGE_MASK;

        RETURN(ldlm_cli_enqueue_local(exp->exp_obd->obd_namespace, &res_id,
                                      LDLM_EXTENT, &policy, mode, &flags,
                                      ldlm_blocking_ast, ldlm_completion_ast,
				      ldlm_glimpse_ast, NULL, 0, LVB_T_NONE,
				      NULL, lh));
}

static void ost_brw_lock_put(int mode,
                             struct obd_ioobj *obj, struct niobuf_remote *niob,
                             struct lustre_handle *lh)
{
        ENTRY;
        LASSERT(mode == LCK_PR || mode == LCK_PW);
        LASSERT((obj->ioo_bufcnt > 0 && (niob[0].flags & OBD_BRW_SRVLOCK)) ==
                lustre_handle_is_used(lh));
        if (lustre_handle_is_used(lh))
                ldlm_lock_decref(lh, mode);
        EXIT;
}

/* Allocate thread local buffers if needed */
static struct ost_thread_local_cache *ost_tls_get(struct ptlrpc_request *r)
{
        struct ost_thread_local_cache *tls =
                (struct ost_thread_local_cache *)(r->rq_svc_thread->t_data);

        /* In normal mode of operation an I/O request is serviced only
         * by ll_ost_io threads each of them has own tls buffers allocated by
         * ost_io_thread_init().
         * During recovery, an I/O request may be queued until any of the ost
         * service threads process it. Not necessary it should be one of
         * ll_ost_io threads. In that case we dynamically allocating tls
         * buffers for the request service time. */
        if (unlikely(tls == NULL)) {
                LASSERT(r->rq_export->exp_in_recovery);
                OBD_ALLOC_PTR(tls);
                if (tls != NULL) {
                        tls->temporary = 1;
                        r->rq_svc_thread->t_data = tls;
                }
        }
        return  tls;
}

/* Free thread local buffers if they were allocated only for servicing
 * this one request */
static void ost_tls_put(struct ptlrpc_request *r)
{
        struct ost_thread_local_cache *tls =
                (struct ost_thread_local_cache *)(r->rq_svc_thread->t_data);

        if (unlikely(tls->temporary)) {
                OBD_FREE_PTR(tls);
                r->rq_svc_thread->t_data = NULL;
        }
}

static int ost_brw_read(struct ptlrpc_request *req, struct obd_trans_info *oti)
{
        struct ptlrpc_bulk_desc *desc = NULL;
        struct obd_export *exp = req->rq_export;
        struct niobuf_remote *remote_nb;
        struct niobuf_local *local_nb;
        struct obd_ioobj *ioo;
        struct ost_body *body, *repbody;
        struct lustre_capa *capa = NULL;
        struct l_wait_info lwi;
        struct lustre_handle lockh = { 0 };
        int niocount, npages, nob = 0, rc, i;
        int no_reply = 0;
        struct ost_thread_local_cache *tls;
        ENTRY;

        req->rq_bulk_read = 1;

        if (OBD_FAIL_CHECK(OBD_FAIL_OST_BRW_READ_BULK))
                GOTO(out, rc = -EIO);

        OBD_FAIL_TIMEOUT(OBD_FAIL_OST_BRW_PAUSE_BULK, (obd_timeout + 1) / 4);

        /* Check if there is eviction in progress, and if so, wait for it to
         * finish */
        if (unlikely(cfs_atomic_read(&exp->exp_obd->obd_evict_inprogress))) {
                lwi = LWI_INTR(NULL, NULL); // We do not care how long it takes
                rc = l_wait_event(exp->exp_obd->obd_evict_inprogress_waitq,
                        !cfs_atomic_read(&exp->exp_obd->obd_evict_inprogress),
                        &lwi);
        }
        if (exp->exp_failed)
                GOTO(out, rc = -ENOTCONN);

        /* ost_body, ioobj & noibuf_remote are verified and swabbed in
         * ost_rw_hpreq_check(). */
        body = req_capsule_client_get(&req->rq_pill, &RMF_OST_BODY);
        if (body == NULL)
                GOTO(out, rc = -EFAULT);

        /*
         * A req_capsule_X_get_array(pill, field, ptr_to_element_count) function
         * would be useful here and wherever we get &RMF_OBD_IOOBJ and
         * &RMF_NIOBUF_REMOTE.
         */
        ioo = req_capsule_client_get(&req->rq_pill, &RMF_OBD_IOOBJ);
        if (ioo == NULL)
                GOTO(out, rc = -EFAULT);

        rc = ost_validate_obdo(exp, &body->oa, ioo);
        if (rc)
                RETURN(rc);

        niocount = ioo->ioo_bufcnt;
        remote_nb = req_capsule_client_get(&req->rq_pill, &RMF_NIOBUF_REMOTE);
        if (remote_nb == NULL)
                GOTO(out, rc = -EFAULT);

        if (body->oa.o_valid & OBD_MD_FLOSSCAPA) {
                capa = req_capsule_client_get(&req->rq_pill, &RMF_CAPA1);
                if (capa == NULL) {
                        CERROR("Missing capability for OST BRW READ");
                        GOTO(out, rc = -EFAULT);
                }
        }

        rc = req_capsule_server_pack(&req->rq_pill);
        if (rc)
                GOTO(out, rc);

        tls = ost_tls_get(req);
        if (tls == NULL)
                GOTO(out_bulk, rc = -ENOMEM);
        local_nb = tls->local;

        rc = ost_brw_lock_get(LCK_PR, exp, ioo, remote_nb, &lockh);
        if (rc != 0)
                GOTO(out_tls, rc);

	/*
	 * If getting the lock took more time than
	 * client was willing to wait, drop it. b=11330
	 */
	if (cfs_time_current_sec() > req->rq_deadline ||
	    OBD_FAIL_CHECK(OBD_FAIL_OST_DROP_REQ)) {
		no_reply = 1;
		CERROR("Dropping timed-out read from %s because locking"
		       "object "DOSTID" took %ld seconds (limit was %ld).\n",
		       libcfs_id2str(req->rq_peer), POSTID(&ioo->ioo_oid),
		       cfs_time_current_sec() - req->rq_arrival_time.tv_sec,
		       req->rq_deadline - req->rq_arrival_time.tv_sec);
		GOTO(out_lock, rc = -ETIMEDOUT);
	}

        repbody = req_capsule_server_get(&req->rq_pill, &RMF_OST_BODY);
        memcpy(&repbody->oa, &body->oa, sizeof(repbody->oa));

        npages = OST_THREAD_POOL_SIZE;
        rc = obd_preprw(req->rq_svc_thread->t_env, OBD_BRW_READ, exp,
                        &repbody->oa, 1, ioo, remote_nb, &npages, local_nb,
                        oti, capa);
        if (rc != 0)
                GOTO(out_lock, rc);

	desc = ptlrpc_prep_bulk_exp(req, npages, ioobj_max_brw_get(ioo),
				    BULK_PUT_SOURCE, OST_BULK_PORTAL);
	if (desc == NULL)
		GOTO(out_commitrw, rc = -ENOMEM);

        nob = 0;
        for (i = 0; i < npages; i++) {
                int page_rc = local_nb[i].rc;

                if (page_rc < 0) {              /* error */
                        rc = page_rc;
                        break;
                }

                nob += page_rc;
                if (page_rc != 0) {             /* some data! */
                        LASSERT (local_nb[i].page != NULL);
			ptlrpc_prep_bulk_page_nopin(desc, local_nb[i].page,
						    local_nb[i].lnb_page_offset,
						    page_rc);
                }

                if (page_rc != local_nb[i].len) { /* short read */
                        /* All subsequent pages should be 0 */
                        while(++i < npages)
                                LASSERT(local_nb[i].rc == 0);
                        break;
                }
        }

        if (body->oa.o_valid & OBD_MD_FLCKSUM) {
                cksum_type_t cksum_type =
                        cksum_type_unpack(repbody->oa.o_valid & OBD_MD_FLFLAGS ?
                                          repbody->oa.o_flags : 0);
                repbody->oa.o_flags = cksum_type_pack(cksum_type);
                repbody->oa.o_valid = OBD_MD_FLCKSUM | OBD_MD_FLFLAGS;
                repbody->oa.o_cksum = ost_checksum_bulk(desc, OST_READ,cksum_type);
                CDEBUG(D_PAGE, "checksum at read origin: %x\n",
                       repbody->oa.o_cksum);
        } else {
                repbody->oa.o_valid = 0;
        }
        /* We're finishing using body->oa as an input variable */

        /* Check if client was evicted while we were doing i/o before touching
           network */
        if (rc == 0) {
                if (likely(!CFS_FAIL_PRECHECK(OBD_FAIL_PTLRPC_CLIENT_BULK_CB2)))
                        rc = target_bulk_io(exp, desc, &lwi);
                no_reply = rc != 0;
        }

out_commitrw:
        /* Must commit after prep above in all cases */
        rc = obd_commitrw(req->rq_svc_thread->t_env, OBD_BRW_READ, exp,
                          &repbody->oa, 1, ioo, remote_nb, npages, local_nb,
                          oti, rc);

        if (rc == 0)
                ost_drop_id(exp, &repbody->oa);

out_lock:
        ost_brw_lock_put(LCK_PR, ioo, remote_nb, &lockh);
out_tls:
        ost_tls_put(req);
out_bulk:
        if (desc && !CFS_FAIL_PRECHECK(OBD_FAIL_PTLRPC_CLIENT_BULK_CB2))
		ptlrpc_free_bulk_nopin(desc);
out:
        LASSERT(rc <= 0);
        if (rc == 0) {
                req->rq_status = nob;
                ptlrpc_lprocfs_brw(req, nob);
                target_committed_to_req(req);
                ptlrpc_reply(req);
        } else if (!no_reply) {
                /* Only reply if there was no comms problem with bulk */
                target_committed_to_req(req);
                req->rq_status = rc;
                ptlrpc_error(req);
        } else {
                /* reply out callback would free */
                ptlrpc_req_drop_rs(req);
                LCONSOLE_WARN("%s: Bulk IO read error with %s (at %s), "
                              "client will retry: rc %d\n",
                              exp->exp_obd->obd_name,
                              obd_uuid2str(&exp->exp_client_uuid),
                              obd_export_nid2str(exp), rc);
        }
        /* send a bulk after reply to simulate a network delay or reordering
         * by a router */
	if (unlikely(CFS_FAIL_PRECHECK(OBD_FAIL_PTLRPC_CLIENT_BULK_CB2))) {
		wait_queue_head_t              waitq;
		struct l_wait_info       lwi1;

		CDEBUG(D_INFO, "reorder BULK\n");
		init_waitqueue_head(&waitq);

		lwi1 = LWI_TIMEOUT_INTR(cfs_time_seconds(3), NULL, NULL, NULL);
		l_wait_event(waitq, 0, &lwi1);
		rc = target_bulk_io(exp, desc, &lwi);
		ptlrpc_free_bulk_nopin(desc);
	}

        RETURN(rc);
}

static void ost_warn_on_cksum(struct ptlrpc_request *req,
			      struct ptlrpc_bulk_desc *desc,
			      struct niobuf_local *local_nb, int npages,
			      obd_count client_cksum, obd_count server_cksum,
			      int mmap)
{
	struct obd_export *exp = req->rq_export;
	struct ost_body *body;
	char *router;
	char *via;

	body = req_capsule_client_get(&req->rq_pill, &RMF_OST_BODY);
	LASSERT	(body != NULL);

	if (req->rq_peer.nid == desc->bd_sender) {
		via = router = "";
	} else {
		via = " via ";
		router = libcfs_nid2str(desc->bd_sender);
	}

	if (mmap) {
		CDEBUG_LIMIT(D_INFO, "client csum %x, server csum %x\n",
			     client_cksum, server_cksum);
		return;
	}

	LCONSOLE_ERROR_MSG(0x168, "BAD WRITE CHECKSUM: %s from %s%s%s inode "
			   DFID" object "DOSTID" extent ["LPU64"-"LPU64
			   "]: client csum %x, server csum %x\n",
			   exp->exp_obd->obd_name, libcfs_id2str(req->rq_peer),
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
			   local_nb[npages-1].len - 1,
			   client_cksum, server_cksum);
}

static int ost_brw_write(struct ptlrpc_request *req, struct obd_trans_info *oti)
{
        struct ptlrpc_bulk_desc *desc = NULL;
        struct obd_export       *exp = req->rq_export;
        struct niobuf_remote    *remote_nb;
        struct niobuf_local     *local_nb;
        struct obd_ioobj        *ioo;
        struct ost_body         *body, *repbody;
        struct l_wait_info       lwi;
        struct lustre_handle     lockh = {0};
        struct lustre_capa      *capa = NULL;
        __u32                   *rcs;
        int objcount, niocount, npages;
        int rc, i, j;
        obd_count                client_cksum = 0, server_cksum = 0;
        cksum_type_t             cksum_type = OBD_CKSUM_CRC32;
        int                      no_reply = 0, mmap = 0;
        __u32                    o_uid = 0, o_gid = 0;
        struct ost_thread_local_cache *tls;
        ENTRY;

        req->rq_bulk_write = 1;

        if (OBD_FAIL_CHECK(OBD_FAIL_OST_BRW_WRITE_BULK))
                GOTO(out, rc = -EIO);
        if (OBD_FAIL_CHECK(OBD_FAIL_OST_BRW_WRITE_BULK2))
                GOTO(out, rc = -EFAULT);

        /* pause before transaction has been started */
        OBD_FAIL_TIMEOUT(OBD_FAIL_OST_BRW_PAUSE_BULK, (obd_timeout + 1) / 4);

        /* ost_body, ioobj & noibuf_remote are verified and swabbed in
         * ost_rw_hpreq_check(). */
        body = req_capsule_client_get(&req->rq_pill, &RMF_OST_BODY);
        if (body == NULL)
                GOTO(out, rc = -EFAULT);

        objcount = req_capsule_get_size(&req->rq_pill, &RMF_OBD_IOOBJ,
                                        RCL_CLIENT) / sizeof(*ioo);
        ioo = req_capsule_client_get(&req->rq_pill, &RMF_OBD_IOOBJ);
        if (ioo == NULL)
                GOTO(out, rc = -EFAULT);

        rc = ost_validate_obdo(exp, &body->oa, ioo);
        if (rc)
                RETURN(rc);

        for (niocount = i = 0; i < objcount; i++)
                niocount += ioo[i].ioo_bufcnt;

        /*
         * It'd be nice to have a capsule function to indicate how many elements
         * there were in a buffer for an RMF that's declared to be an array.
         * It's easy enough to compute the number of elements here though.
         */
        remote_nb = req_capsule_client_get(&req->rq_pill, &RMF_NIOBUF_REMOTE);
        if (remote_nb == NULL || niocount != (req_capsule_get_size(&req->rq_pill,
            &RMF_NIOBUF_REMOTE, RCL_CLIENT) / sizeof(*remote_nb)))
                GOTO(out, rc = -EFAULT);

        if ((remote_nb[0].flags & OBD_BRW_MEMALLOC) &&
            (exp->exp_connection->c_peer.nid == exp->exp_connection->c_self))
		memory_pressure_set();

        if (body->oa.o_valid & OBD_MD_FLOSSCAPA) {
                capa = req_capsule_client_get(&req->rq_pill, &RMF_CAPA1);
                if (capa == NULL) {
                        CERROR("Missing capability for OST BRW WRITE");
                        GOTO(out, rc = -EFAULT);
                }
        }

        req_capsule_set_size(&req->rq_pill, &RMF_RCS, RCL_SERVER,
                             niocount * sizeof(*rcs));
        rc = req_capsule_server_pack(&req->rq_pill);
        if (rc != 0)
                GOTO(out, rc);
        CFS_FAIL_TIMEOUT(OBD_FAIL_OST_BRW_PAUSE_PACK, cfs_fail_val);
        rcs = req_capsule_server_get(&req->rq_pill, &RMF_RCS);

        tls = ost_tls_get(req);
        if (tls == NULL)
                GOTO(out_bulk, rc = -ENOMEM);
        local_nb = tls->local;

        rc = ost_brw_lock_get(LCK_PW, exp, ioo, remote_nb, &lockh);
        if (rc != 0)
                GOTO(out_tls, rc);

	/*
	 * If getting the lock took more time than
	 * client was willing to wait, drop it. b=11330
	 */
	if (cfs_time_current_sec() > req->rq_deadline ||
	    OBD_FAIL_CHECK(OBD_FAIL_OST_DROP_REQ)) {
		no_reply = 1;
		CERROR("Dropping timed-out write from %s because locking "
		       "object "DOSTID" took %ld seconds (limit was %ld).\n",
		       libcfs_id2str(req->rq_peer), POSTID(&ioo->ioo_oid),
		       cfs_time_current_sec() - req->rq_arrival_time.tv_sec,
		       req->rq_deadline - req->rq_arrival_time.tv_sec);
		GOTO(out_lock, rc = -ETIMEDOUT);
	}

        /* obd_preprw clobbers oa->valid, so save what we need */
        if (body->oa.o_valid & OBD_MD_FLCKSUM) {
                client_cksum = body->oa.o_cksum;
                if (body->oa.o_valid & OBD_MD_FLFLAGS)
                        cksum_type = cksum_type_unpack(body->oa.o_flags);
        }
        if (body->oa.o_valid & OBD_MD_FLFLAGS && body->oa.o_flags & OBD_FL_MMAP)
                mmap = 1;

        /* Because we already sync grant info with client when reconnect,
         * grant info will be cleared for resent req, then fed_grant and
         * total_grant will not be modified in following preprw_write */
        if (lustre_msg_get_flags(req->rq_reqmsg) & (MSG_RESENT | MSG_REPLAY)) {
                DEBUG_REQ(D_CACHE, req, "clear resent/replay req grant info");
                body->oa.o_valid &= ~OBD_MD_FLGRANT;
        }

        if (exp_connect_rmtclient(exp)) {
                o_uid = body->oa.o_uid;
                o_gid = body->oa.o_gid;
        }

        repbody = req_capsule_server_get(&req->rq_pill, &RMF_OST_BODY);
        memcpy(&repbody->oa, &body->oa, sizeof(repbody->oa));

        npages = OST_THREAD_POOL_SIZE;
        rc = obd_preprw(req->rq_svc_thread->t_env, OBD_BRW_WRITE, exp,
                        &repbody->oa, objcount, ioo, remote_nb, &npages,
                        local_nb, oti, capa);
        if (rc != 0)
                GOTO(out_lock, rc);

	desc = ptlrpc_prep_bulk_exp(req, npages, ioobj_max_brw_get(ioo),
				    BULK_GET_SINK, OST_BULK_PORTAL);
	if (desc == NULL)
		GOTO(skip_transfer, rc = -ENOMEM);

	/* NB Having prepped, we must commit... */
	for (i = 0; i < npages; i++)
		ptlrpc_prep_bulk_page_nopin(desc, local_nb[i].page,
					    local_nb[i].lnb_page_offset,
					    local_nb[i].len);

        rc = sptlrpc_svc_prep_bulk(req, desc);
        if (rc != 0)
                GOTO(out_lock, rc);

        rc = target_bulk_io(exp, desc, &lwi);
        no_reply = rc != 0;

skip_transfer:
        if (client_cksum != 0 && rc == 0) {
                static int cksum_counter;
                repbody->oa.o_valid |= OBD_MD_FLCKSUM | OBD_MD_FLFLAGS;
                repbody->oa.o_flags &= ~OBD_FL_CKSUM_ALL;
                repbody->oa.o_flags |= cksum_type_pack(cksum_type);
                server_cksum = ost_checksum_bulk(desc, OST_WRITE, cksum_type);
                repbody->oa.o_cksum = server_cksum;
                cksum_counter++;
                if (unlikely(client_cksum != server_cksum)) {
			ost_warn_on_cksum(req, desc, local_nb, npages,
					  client_cksum, server_cksum, mmap);
                        cksum_counter = 0;

                } else if ((cksum_counter & (-cksum_counter)) == cksum_counter){
                        CDEBUG(D_INFO, "Checksum %u from %s OK: %x\n",
                               cksum_counter, libcfs_id2str(req->rq_peer),
                               server_cksum);
                }
        }

        /* Must commit after prep above in all cases */
        rc = obd_commitrw(req->rq_svc_thread->t_env, OBD_BRW_WRITE, exp,
                          &repbody->oa, objcount, ioo, remote_nb, npages,
                          local_nb, oti, rc);
        if (rc == -ENOTCONN)
                /* quota acquire process has been given up because
                 * either the client has been evicted or the client
                 * has timed out the request already */
                no_reply = 1;

        if (exp_connect_rmtclient(exp)) {
                repbody->oa.o_uid = o_uid;
                repbody->oa.o_gid = o_gid;
        }

        /*
         * Disable sending mtime back to the client. If the client locked the
         * whole object, then it has already updated the mtime on its side,
         * otherwise it will have to glimpse anyway (see bug 21489, comment 32)
         */
        repbody->oa.o_valid &= ~(OBD_MD_FLMTIME | OBD_MD_FLATIME);

        if (rc == 0) {
                int nob = 0;

                /* set per-requested niobuf return codes */
                for (i = j = 0; i < niocount; i++) {
                        int len = remote_nb[i].len;

                        nob += len;
                        rcs[i] = 0;
                        do {
                                LASSERT(j < npages);
                                if (local_nb[j].rc < 0)
                                        rcs[i] = local_nb[j].rc;
                                len -= local_nb[j].len;
                                j++;
                        } while (len > 0);
                        LASSERT(len == 0);
                }
                LASSERT(j == npages);
                ptlrpc_lprocfs_brw(req, nob);
        }

out_lock:
        ost_brw_lock_put(LCK_PW, ioo, remote_nb, &lockh);
out_tls:
        ost_tls_put(req);
out_bulk:
        if (desc)
		ptlrpc_free_bulk_nopin(desc);
out:
        if (rc == 0) {
                oti_to_request(oti, req);
                target_committed_to_req(req);
                rc = ptlrpc_reply(req);
        } else if (!no_reply) {
                /* Only reply if there was no comms problem with bulk */
                target_committed_to_req(req);
                req->rq_status = rc;
                ptlrpc_error(req);
        } else {
                /* reply out callback would free */
                ptlrpc_req_drop_rs(req);
                LCONSOLE_WARN("%s: Bulk IO write error with %s (at %s), "
                              "client will retry: rc %d\n",
                              exp->exp_obd->obd_name,
                              obd_uuid2str(&exp->exp_client_uuid),
                              obd_export_nid2str(exp), rc);
        }
	memory_pressure_clr();
        RETURN(rc);
}

/**
 * Implementation of OST_SET_INFO.
 *
 * OST_SET_INFO is like ioctl(): heavily overloaded.  Specifically, it takes a
 * "key" and a value RPC buffers as arguments, with the value's contents
 * interpreted according to the key.
 *
 * Value types that need swabbing have swabbing done explicitly, either here or
 * in functions called from here.  This should be corrected: all swabbing should
 * be done in the capsule abstraction, as that will then allow us to move
 * swabbing exclusively to the client without having to modify server code
 * outside the capsule abstraction's implementation itself.  To correct this
 * will require minor changes to the capsule abstraction; see the comments for
 * req_capsule_extend() in layout.c.
 */
static int ost_set_info(struct obd_export *exp, struct ptlrpc_request *req)
{
        struct ost_body *body = NULL, *repbody;
        char *key, *val = NULL;
        int keylen, vallen, rc = 0;
        int is_grant_shrink = 0;
        ENTRY;

        key = req_capsule_client_get(&req->rq_pill, &RMF_SETINFO_KEY);
        if (key == NULL) {
                DEBUG_REQ(D_HA, req, "no set_info key");
                RETURN(-EFAULT);
        }
        keylen = req_capsule_get_size(&req->rq_pill, &RMF_SETINFO_KEY,
                                      RCL_CLIENT);

        vallen = req_capsule_get_size(&req->rq_pill, &RMF_SETINFO_VAL,
                                      RCL_CLIENT);

        if ((is_grant_shrink = KEY_IS(KEY_GRANT_SHRINK)))
                /* In this case the value is actually an RMF_OST_BODY, so we
                 * transmutate the type of this PTLRPC */
                req_capsule_extend(&req->rq_pill, &RQF_OST_SET_GRANT_INFO);

        rc = req_capsule_server_pack(&req->rq_pill);
        if (rc)
                RETURN(rc);

        if (vallen) {
                if (is_grant_shrink) {
                        body = req_capsule_client_get(&req->rq_pill,
                                                      &RMF_OST_BODY);
                        if (!body)
                                RETURN(-EFAULT);

                        repbody = req_capsule_server_get(&req->rq_pill,
                                                         &RMF_OST_BODY);
                        memcpy(repbody, body, sizeof(*body));
                        val = (char*)repbody;
                } else {
                        val = req_capsule_client_get(&req->rq_pill,
                                                     &RMF_SETINFO_VAL);
                }
        }

        if (KEY_IS(KEY_EVICT_BY_NID)) {
                if (val && vallen)
                        obd_export_evict_by_nid(exp->exp_obd, val);
                GOTO(out, rc = 0);
        } else if (KEY_IS(KEY_MDS_CONN) && ptlrpc_req_need_swab(req)) {
                if (vallen < sizeof(__u32))
                        RETURN(-EFAULT);
                __swab32s((__u32 *)val);
        }

        /* OBD will also check if KEY_IS(KEY_GRANT_SHRINK), and will cast val to
         * a struct ost_body * value */
        rc = obd_set_info_async(req->rq_svc_thread->t_env, exp, keylen,
                                key, vallen, val, NULL);
out:
        lustre_msg_set_status(req->rq_repmsg, 0);
        RETURN(rc);
}

struct locked_region {
	cfs_list_t  list;
	struct lustre_handle lh;
};

static int lock_region(struct obd_export *exp, struct obdo *oa,
		       unsigned long long begin, unsigned long long end,
		       cfs_list_t *locked)
{
	struct locked_region *region = NULL;
	int rc;

	LASSERT(begin <= end);
	OBD_ALLOC_PTR(region);
	if (region == NULL)
		return -ENOMEM;

	rc = ost_lock_get(exp, oa, begin, end - begin, &region->lh, LCK_PR, 0);
	if (rc) {
		OBD_FREE_PTR(region);
		return rc;
	}

	CDEBUG(D_OTHER, "ost lock [%llu,%llu], lh=%p\n",
	       begin, end, &region->lh);
	cfs_list_add(&region->list, locked);

	return 0;
}

static int lock_zero_regions(struct obd_export *exp, struct obdo *oa,
			     struct ll_user_fiemap *fiemap,
			     cfs_list_t *locked)
{
	__u64 begin = fiemap->fm_start;
	unsigned int i;
	int rc = 0;
	struct ll_fiemap_extent *fiemap_start = fiemap->fm_extents;
	ENTRY;

	CDEBUG(D_OTHER, "extents count %u\n", fiemap->fm_mapped_extents);
	for (i = 0; i < fiemap->fm_mapped_extents; i++) {
		if (fiemap_start[i].fe_logical > begin) {
			CDEBUG(D_OTHER, "ost lock [%llu,%llu]\n",
			       begin, fiemap_start[i].fe_logical);
			rc = lock_region(exp, oa, begin,
				    fiemap_start[i].fe_logical, locked);
			if (rc)
				RETURN(rc);
		}

		begin = fiemap_start[i].fe_logical + fiemap_start[i].fe_length;
	}

	if (begin < (fiemap->fm_start + fiemap->fm_length)) {
		CDEBUG(D_OTHER, "ost lock [%llu,%llu]\n",
		       begin, fiemap->fm_start + fiemap->fm_length);
		rc = lock_region(exp, oa, begin,
				 fiemap->fm_start + fiemap->fm_length, locked);
	}

	RETURN(rc);
}

static void unlock_zero_regions(struct obd_export *exp, cfs_list_t *locked)
{
	struct locked_region *entry, *temp;
	cfs_list_for_each_entry_safe(entry, temp, locked, list) {
		CDEBUG(D_OTHER, "ost unlock lh=%p\n", &entry->lh);
		ost_lock_put(exp, &entry->lh, LCK_PR);
		cfs_list_del(&entry->list);
		OBD_FREE_PTR(entry);
	}
}

static int ost_get_info(struct obd_export *exp, struct ptlrpc_request *req)
{
        void *key, *reply;
        int keylen, replylen, rc = 0;
        struct req_capsule *pill = &req->rq_pill;
	cfs_list_t locked = CFS_LIST_HEAD_INIT(locked);
	struct ll_fiemap_info_key *fm_key = NULL;
	struct ll_user_fiemap *fiemap;
        ENTRY;

        /* this common part for get_info rpc */
        key = req_capsule_client_get(pill, &RMF_SETINFO_KEY);
        if (key == NULL) {
                DEBUG_REQ(D_HA, req, "no get_info key");
                RETURN(-EFAULT);
        }
        keylen = req_capsule_get_size(pill, &RMF_SETINFO_KEY, RCL_CLIENT);

        if (KEY_IS(KEY_FIEMAP)) {
		fm_key = key;
                rc = ost_validate_obdo(exp, &fm_key->oa, NULL);
                if (rc)
                        RETURN(rc);
	}

        rc = obd_get_info(req->rq_svc_thread->t_env, exp, keylen, key,
                          &replylen, NULL, NULL);
        if (rc)
		RETURN(rc);

        req_capsule_set_size(pill, &RMF_GENERIC_DATA,
                             RCL_SERVER, replylen);

        rc = req_capsule_server_pack(pill);
        if (rc)
		RETURN(rc);

        reply = req_capsule_server_get(pill, &RMF_GENERIC_DATA);
        if (reply == NULL)
		RETURN(-ENOMEM);

	if (KEY_IS(KEY_LAST_FID)) {
		void *val;
		int vallen;

		req_capsule_extend(pill, &RQF_OST_GET_INFO_LAST_FID);
		val = req_capsule_client_get(pill, &RMF_SETINFO_VAL);
		vallen = req_capsule_get_size(pill, &RMF_SETINFO_VAL,
					      RCL_CLIENT);
		if (val != NULL && vallen > 0 && replylen >= vallen) {
			memcpy(reply, val, vallen);
		} else {
			CERROR("%s: invalid req val %p vallen %d replylen %d\n",
			       exp->exp_obd->obd_name, val, vallen, replylen);
			RETURN(-EINVAL);
		}
	}

	/* call again to fill in the reply buffer */
	rc = obd_get_info(req->rq_svc_thread->t_env, exp, keylen, key,
			  &replylen, reply, NULL);

	/* LU-3219: Lock the sparse areas to make sure dirty flushed back
	 * from client, then call fiemap again. */
	if (KEY_IS(KEY_FIEMAP) && (fm_key->oa.o_valid & OBD_MD_FLFLAGS) &&
	    (fm_key->oa.o_flags & OBD_FL_SRVLOCK)) {
		fiemap = (struct ll_user_fiemap *)reply;
		fm_key = key;

		rc = lock_zero_regions(exp, &fm_key->oa, fiemap, &locked);
		if (rc == 0 && !cfs_list_empty(&locked))
			rc = obd_get_info(req->rq_svc_thread->t_env, exp,
					  keylen, key, &replylen, reply, NULL);
		unlock_zero_regions(exp, &locked);
		if (rc)
			RETURN(rc);
	}

	lustre_msg_set_status(req->rq_repmsg, 0);

        RETURN(rc);
}

static int ost_handle_quotactl(struct ptlrpc_request *req)
{
        struct obd_quotactl *oqctl, *repoqc;
        int rc;
        ENTRY;

        oqctl = req_capsule_client_get(&req->rq_pill, &RMF_OBD_QUOTACTL);
        if (oqctl == NULL)
                GOTO(out, rc = -EPROTO);

        rc = req_capsule_server_pack(&req->rq_pill);
        if (rc)
                GOTO(out, rc);

        repoqc = req_capsule_server_get(&req->rq_pill, &RMF_OBD_QUOTACTL);
        req->rq_status = obd_quotactl(req->rq_export, oqctl);
        *repoqc = *oqctl;

out:
        RETURN(rc);
}

static int ost_handle_quotacheck(struct ptlrpc_request *req)
{
        struct obd_quotactl *oqctl;
        int rc;
        ENTRY;

        oqctl = req_capsule_client_get(&req->rq_pill, &RMF_OBD_QUOTACTL);
        if (oqctl == NULL)
                RETURN(-EPROTO);

        rc = req_capsule_server_pack(&req->rq_pill);
        if (rc)
                RETURN(-ENOMEM);

	/* deprecated, not used any more */
	req->rq_status = -EOPNOTSUPP;
	RETURN(-EOPNOTSUPP);
}

static int ost_llog_handle_connect(struct obd_export *exp,
                                   struct ptlrpc_request *req)
{
        struct llogd_conn_body *body;
        int rc;
        ENTRY;

        body = req_capsule_client_get(&req->rq_pill, &RMF_LLOGD_CONN_BODY);
        rc = obd_llog_connect(exp, body);
        RETURN(rc);
}

#define ost_init_sec_none(reply)					\
do {									\
	reply->ocd_connect_flags &= ~(OBD_CONNECT_RMT_CLIENT |		\
				      OBD_CONNECT_RMT_CLIENT_FORCE |	\
				      OBD_CONNECT_OSS_CAPA);		\
} while (0)

static int ost_init_sec_level(struct ptlrpc_request *req)
{
        struct obd_export *exp = req->rq_export;
        struct req_capsule *pill = &req->rq_pill;
        struct obd_device *obd = exp->exp_obd;
        struct filter_obd *filter = &obd->u.filter;
        char *client = libcfs_nid2str(req->rq_peer.nid);
        struct obd_connect_data *data, *reply;
        int rc = 0, remote;
        ENTRY;

        data = req_capsule_client_get(pill, &RMF_CONNECT_DATA);
        reply = req_capsule_server_get(pill, &RMF_CONNECT_DATA);
        if (data == NULL || reply == NULL)
                RETURN(-EFAULT);

        /* connection from MDT is always trusted */
        if (req->rq_auth_usr_mdt) {
		ost_init_sec_none(reply);
                RETURN(0);
        }

        /* no GSS support case */
        if (!req->rq_auth_gss) {
                if (filter->fo_sec_level > LUSTRE_SEC_NONE) {
                        CWARN("client %s -> target %s does not user GSS, "
                              "can not run under security level %d.\n",
                              client, obd->obd_name, filter->fo_sec_level);
                        RETURN(-EACCES);
                } else {
			ost_init_sec_none(reply);
                        RETURN(0);
                }
        }

        /* old version case */
        if (unlikely(!(data->ocd_connect_flags & OBD_CONNECT_RMT_CLIENT) ||
                     !(data->ocd_connect_flags & OBD_CONNECT_OSS_CAPA))) {
                if (filter->fo_sec_level > LUSTRE_SEC_NONE) {
                        CWARN("client %s -> target %s uses old version, "
                              "can not run under security level %d.\n",
                              client, obd->obd_name, filter->fo_sec_level);
                        RETURN(-EACCES);
                } else {
                        CWARN("client %s -> target %s uses old version, "
                              "run under security level %d.\n",
                              client, obd->obd_name, filter->fo_sec_level);
			ost_init_sec_none(reply);
                        RETURN(0);
                }
        }

        remote = data->ocd_connect_flags & OBD_CONNECT_RMT_CLIENT_FORCE;
        if (remote) {
                if (!req->rq_auth_remote)
                        CDEBUG(D_SEC, "client (local realm) %s -> target %s "
                               "asked to be remote.\n", client, obd->obd_name);
        } else if (req->rq_auth_remote) {
                remote = 1;
                CDEBUG(D_SEC, "client (remote realm) %s -> target %s is set "
                       "as remote by default.\n", client, obd->obd_name);
        }

        if (remote) {
                if (!filter->fo_fl_oss_capa) {
                        CDEBUG(D_SEC, "client %s -> target %s is set as remote,"
                               " but OSS capabilities are not enabled: %d.\n",
                               client, obd->obd_name, filter->fo_fl_oss_capa);
                        RETURN(-EACCES);
                }
        }

        switch (filter->fo_sec_level) {
        case LUSTRE_SEC_NONE:
                if (!remote) {
			ost_init_sec_none(reply);
                        break;
                } else {
                        CDEBUG(D_SEC, "client %s -> target %s is set as remote, "
                               "can not run under security level %d.\n",
                               client, obd->obd_name, filter->fo_sec_level);
                        RETURN(-EACCES);
                }
        case LUSTRE_SEC_REMOTE:
                if (!remote)
			ost_init_sec_none(reply);
                break;
        case LUSTRE_SEC_ALL:
                if (!remote) {
                        reply->ocd_connect_flags &= ~(OBD_CONNECT_RMT_CLIENT |
                                                      OBD_CONNECT_RMT_CLIENT_FORCE);
                        if (!filter->fo_fl_oss_capa)
                                reply->ocd_connect_flags &= ~OBD_CONNECT_OSS_CAPA;
                }
                break;
        default:
                RETURN(-EINVAL);
        }

        RETURN(rc);
}

/*
 * FIXME
 * this should be done in filter_connect()/filter_reconnect(), but
 * we can't obtain information like NID, which stored in incoming
 * request, thus can't decide what flavor to use. so we do it here.
 *
 * This hack should be removed after the OST stack be rewritten, just
 * like what we are doing in mdt_obd_connect()/mdt_obd_reconnect().
 */
static int ost_connect_check_sptlrpc(struct ptlrpc_request *req)
{
        struct obd_export     *exp = req->rq_export;
        struct filter_obd     *filter = &exp->exp_obd->u.filter;
        struct sptlrpc_flavor  flvr;
        int                    rc = 0;

        if (unlikely(strcmp(exp->exp_obd->obd_type->typ_name,
                            LUSTRE_ECHO_NAME) == 0)) {
                exp->exp_flvr.sf_rpc = SPTLRPC_FLVR_ANY;
                return 0;
        }

        if (exp->exp_flvr.sf_rpc == SPTLRPC_FLVR_INVALID) {
		read_lock(&filter->fo_sptlrpc_lock);
		sptlrpc_target_choose_flavor(&filter->fo_sptlrpc_rset,
					     req->rq_sp_from,
					     req->rq_peer.nid,
					     &flvr);
		read_unlock(&filter->fo_sptlrpc_lock);

		spin_lock(&exp->exp_lock);

                exp->exp_sp_peer = req->rq_sp_from;
                exp->exp_flvr = flvr;

                if (exp->exp_flvr.sf_rpc != SPTLRPC_FLVR_ANY &&
                    exp->exp_flvr.sf_rpc != req->rq_flvr.sf_rpc) {
                        CERROR("unauthorized rpc flavor %x from %s, "
                               "expect %x\n", req->rq_flvr.sf_rpc,
                               libcfs_nid2str(req->rq_peer.nid),
                               exp->exp_flvr.sf_rpc);
                        rc = -EACCES;
                }

		spin_unlock(&exp->exp_lock);
        } else {
                if (exp->exp_sp_peer != req->rq_sp_from) {
                        CERROR("RPC source %s doesn't match %s\n",
                               sptlrpc_part2name(req->rq_sp_from),
                               sptlrpc_part2name(exp->exp_sp_peer));
                        rc = -EACCES;
                } else {
                        rc = sptlrpc_target_export_check(exp, req);
                }
        }

        return rc;
}

/* Ensure that data and metadata are synced to the disk when lock is cancelled
 * (if requested) */
int ost_blocking_ast(struct ldlm_lock *lock, struct ldlm_lock_desc *desc,
		     void *data, int flag)
{
	struct lu_env	env;
	__u32		sync_lock_cancel = 0;
	__u32		len = sizeof(sync_lock_cancel);
	int		rc = 0;

	ENTRY;

	rc = lu_env_init(&env, LCT_DT_THREAD);
	if (unlikely(rc != 0))
		RETURN(rc);

	rc = obd_get_info(&env, lock->l_export, sizeof(KEY_SYNC_LOCK_CANCEL),
			  KEY_SYNC_LOCK_CANCEL, &len, &sync_lock_cancel, NULL);
	if (rc == 0 && flag == LDLM_CB_CANCELING &&
	    (lock->l_granted_mode & (LCK_PW|LCK_GROUP)) &&
	    (sync_lock_cancel == ALWAYS_SYNC_ON_CANCEL ||
	     (sync_lock_cancel == BLOCKING_SYNC_ON_CANCEL &&
	      lock->l_flags & LDLM_FL_CBPENDING))) {
		struct obd_info	*oinfo;
		struct obdo	*oa;
		int		 rc;

		OBD_ALLOC_PTR(oinfo);
		if (!oinfo)
			GOTO(out_env, rc = -ENOMEM);
		OBDO_ALLOC(oa);
		if (!oa) {
			OBD_FREE_PTR(oinfo);
			GOTO(out_env, rc = -ENOMEM);
		}

		ostid_res_name_to_id(&oa->o_oi, &lock->l_resource->lr_name);
		oa->o_valid = OBD_MD_FLID|OBD_MD_FLGROUP;
		oinfo->oi_oa = oa;
		oinfo->oi_capa = BYPASS_CAPA;

		rc = obd_sync(&env, lock->l_export, oinfo,
			      lock->l_policy_data.l_extent.start,
			      lock->l_policy_data.l_extent.end, NULL);
		if (rc)
			CERROR("Error %d syncing data on lock cancel\n", rc);

		OBDO_FREE(oa);
		OBD_FREE_PTR(oinfo);
	}

	rc = ldlm_server_blocking_ast(lock, desc, data, flag);
out_env:
	lu_env_fini(&env);
	RETURN(rc);
}

static int ost_filter_recovery_request(struct ptlrpc_request *req,
                                       struct obd_device *obd, int *process)
{
        switch (lustre_msg_get_opc(req->rq_reqmsg)) {
        case OST_CONNECT: /* This will never get here, but for completeness. */
        case OST_DISCONNECT:
               *process = 1;
               RETURN(0);

        case OBD_PING:
        case OST_CREATE:
        case OST_DESTROY:
        case OST_PUNCH:
        case OST_SETATTR:
        case OST_SYNC:
        case OST_WRITE:
        case OBD_LOG_CANCEL:
        case LDLM_ENQUEUE:
                *process = target_queue_recovery_request(req, obd);
                RETURN(0);

        default:
                DEBUG_REQ(D_WARNING, req, "not permitted during recovery");
                *process = -EAGAIN;
                RETURN(0);
        }
}

int ost_msg_check_version(struct lustre_msg *msg)
{
        int rc;

        switch(lustre_msg_get_opc(msg)) {
        case OST_CONNECT:
        case OST_DISCONNECT:
        case OBD_PING:
        case SEC_CTX_INIT:
        case SEC_CTX_INIT_CONT:
        case SEC_CTX_FINI:
                rc = lustre_msg_check_version(msg, LUSTRE_OBD_VERSION);
                if (rc)
                        CERROR("bad opc %u version %08x, expecting %08x\n",
                               lustre_msg_get_opc(msg),
                               lustre_msg_get_version(msg),
                               LUSTRE_OBD_VERSION);
                break;
        case OST_CREATE:
        case OST_DESTROY:
        case OST_GETATTR:
        case OST_SETATTR:
        case OST_WRITE:
        case OST_READ:
        case OST_PUNCH:
        case OST_STATFS:
        case OST_SYNC:
        case OST_SET_INFO:
        case OST_GET_INFO:
        case OST_QUOTACHECK:
        case OST_QUOTACTL:
                rc = lustre_msg_check_version(msg, LUSTRE_OST_VERSION);
                if (rc)
                        CERROR("bad opc %u version %08x, expecting %08x\n",
                               lustre_msg_get_opc(msg),
                               lustre_msg_get_version(msg),
                               LUSTRE_OST_VERSION);
                break;
        case LDLM_ENQUEUE:
        case LDLM_CONVERT:
        case LDLM_CANCEL:
        case LDLM_BL_CALLBACK:
        case LDLM_CP_CALLBACK:
                rc = lustre_msg_check_version(msg, LUSTRE_DLM_VERSION);
                if (rc)
                        CERROR("bad opc %u version %08x, expecting %08x\n",
                               lustre_msg_get_opc(msg),
                               lustre_msg_get_version(msg),
                               LUSTRE_DLM_VERSION);
                break;
        case LLOG_ORIGIN_CONNECT:
        case OBD_LOG_CANCEL:
                rc = lustre_msg_check_version(msg, LUSTRE_LOG_VERSION);
                if (rc)
                        CERROR("bad opc %u version %08x, expecting %08x\n",
                               lustre_msg_get_opc(msg),
                               lustre_msg_get_version(msg),
                               LUSTRE_LOG_VERSION);
                break;
	case OST_QUOTA_ADJUST_QUNIT:
		rc = -ENOTSUPP;
		CERROR("Quota adjust is deprecated as of 2.4.0\n");
		break;
        default:
                CERROR("Unexpected opcode %d\n", lustre_msg_get_opc(msg));
                rc = -ENOTSUPP;
        }
        return rc;
}

struct ost_prolong_data {
        struct ptlrpc_request *opd_req;
        struct obd_export     *opd_exp;
        struct obdo           *opd_oa;
        struct ldlm_res_id     opd_resid;
        struct ldlm_extent     opd_extent;
        ldlm_mode_t            opd_mode;
        unsigned int           opd_locks;
        int                    opd_timeout;
};

/* prolong locks for the current service time of the corresponding
 * portal (= OST_IO_PORTAL)
 */
static inline int prolong_timeout(struct ptlrpc_request *req)
{
	struct ptlrpc_service_part *svcpt = req->rq_rqbd->rqbd_svcpt;

	if (AT_OFF)
		return obd_timeout / 2;

	return max(at_est2timeout(at_get(&svcpt->scp_at_estimate)),
		   ldlm_timeout);
}

static void ost_prolong_lock_one(struct ost_prolong_data *opd,
                                 struct ldlm_lock *lock)
{
	LASSERT(lock->l_export == opd->opd_exp);

	if (lock->l_flags & LDLM_FL_DESTROYED) /* lock already cancelled */
		return;

        /* XXX: never try to grab resource lock here because we're inside
         * exp_bl_list_lock; in ldlm_lockd.c to handle waiting list we take
         * res lock and then exp_bl_list_lock. */

        if (!(lock->l_flags & LDLM_FL_AST_SENT))
                /* ignore locks not being cancelled */
                return;

        LDLM_DEBUG(lock,
                   "refreshed for req x"LPU64" ext("LPU64"->"LPU64") to %ds.\n",
                   opd->opd_req->rq_xid, opd->opd_extent.start,
                   opd->opd_extent.end, opd->opd_timeout);

        /* OK. this is a possible lock the user holds doing I/O
         * let's refresh eviction timer for it */
        ldlm_refresh_waiting_lock(lock, opd->opd_timeout);
        ++opd->opd_locks;
}

static void ost_prolong_locks(struct ost_prolong_data *data)
{
        struct obd_export *exp = data->opd_exp;
        struct obdo       *oa  = data->opd_oa;
        struct ldlm_lock  *lock;
        ENTRY;

        if (oa->o_valid & OBD_MD_FLHANDLE) {
                /* mostly a request should be covered by only one lock, try
                 * fast path. */
                lock = ldlm_handle2lock(&oa->o_handle);
                if (lock != NULL) {
                        /* Fast path to check if the lock covers the whole IO
                         * region exclusively. */
                        if (lock->l_granted_mode == LCK_PW &&
                            ldlm_extent_contain(&lock->l_policy_data.l_extent,
                                                &data->opd_extent)) {
                                /* bingo */
                                ost_prolong_lock_one(data, lock);
                                LDLM_LOCK_PUT(lock);
                                RETURN_EXIT;
                        }
                        LDLM_LOCK_PUT(lock);
                }
        }


	spin_lock_bh(&exp->exp_bl_list_lock);
        cfs_list_for_each_entry(lock, &exp->exp_bl_list, l_exp_list) {
                LASSERT(lock->l_flags & LDLM_FL_AST_SENT);
                LASSERT(lock->l_resource->lr_type == LDLM_EXTENT);

                if (!ldlm_res_eq(&data->opd_resid, &lock->l_resource->lr_name))
                        continue;

                if (!ldlm_extent_overlap(&lock->l_policy_data.l_extent,
                                         &data->opd_extent))
                        continue;

                ost_prolong_lock_one(data, lock);
        }
	spin_unlock_bh(&exp->exp_bl_list_lock);

	EXIT;
}

/**
 * Returns 1 if the given PTLRPC matches the given LDLM locks, or 0 if it does
 * not.
 */
static int ost_rw_hpreq_lock_match(struct ptlrpc_request *req,
                                   struct ldlm_lock *lock)
{
        struct niobuf_remote *nb;
        struct obd_ioobj *ioo;
        int mode, opc;
        struct ldlm_extent ext;
        ENTRY;

        opc = lustre_msg_get_opc(req->rq_reqmsg);
        LASSERT(opc == OST_READ || opc == OST_WRITE);

        ioo = req_capsule_client_get(&req->rq_pill, &RMF_OBD_IOOBJ);
        LASSERT(ioo != NULL);

        nb = req_capsule_client_get(&req->rq_pill, &RMF_NIOBUF_REMOTE);
        LASSERT(nb != NULL);

        ext.start = nb->offset;
        nb += ioo->ioo_bufcnt - 1;
        ext.end = nb->offset + nb->len - 1;

	LASSERT(lock->l_resource != NULL);
	if (!ostid_res_name_eq(&ioo->ioo_oid, &lock->l_resource->lr_name))
		RETURN(0);

	/* a bulk write can only hold a reference on a PW extent lock */
	mode = LCK_PW;
	if (opc == OST_READ)
		/* whereas a bulk read can be protected by either a PR or PW
		 * extent lock */
		mode |= LCK_PR;
        if (!(lock->l_granted_mode & mode))
                RETURN(0);

        RETURN(ldlm_extent_overlap(&lock->l_policy_data.l_extent, &ext));
}

/**
 * High-priority queue request check for whether the given PTLRPC request (\a
 * req) is blocking an LDLM lock cancel.
 *
 * Returns 1 if the given given PTLRPC request (\a req) is blocking an LDLM lock
 * cancel, 0 if it is not, and -EFAULT if the request is malformed.
 *
 * Only OST_READs, OST_WRITEs and OST_PUNCHes go on the h-p RPC queue.  This
 * function looks only at OST_READs and OST_WRITEs.
 */
static int ost_rw_hpreq_check(struct ptlrpc_request *req)
{
        struct obd_device *obd = req->rq_export->exp_obd;
        struct ost_body *body;
        struct obd_ioobj *ioo;
        struct niobuf_remote *nb;
        struct ost_prolong_data opd = { 0 };
        int mode, opc;
        ENTRY;

        /*
         * Use LASSERT to do sanity check because malformed RPCs should have
         * been filtered out in ost_hpreq_handler().
         */
        opc = lustre_msg_get_opc(req->rq_reqmsg);
        LASSERT(opc == OST_READ || opc == OST_WRITE);

        body = req_capsule_client_get(&req->rq_pill, &RMF_OST_BODY);
        LASSERT(body != NULL);

        ioo = req_capsule_client_get(&req->rq_pill, &RMF_OBD_IOOBJ);
        LASSERT(ioo != NULL);

        nb = req_capsule_client_get(&req->rq_pill, &RMF_NIOBUF_REMOTE);
        LASSERT(nb != NULL);
        LASSERT(!(nb->flags & OBD_BRW_SRVLOCK));

	ostid_build_res_name(&ioo->ioo_oid, &opd.opd_resid);

        opd.opd_req = req;
        mode = LCK_PW;
        if (opc == OST_READ)
                mode |= LCK_PR;
        opd.opd_mode = mode;
        opd.opd_exp = req->rq_export;
        opd.opd_oa  = &body->oa;
        opd.opd_extent.start = nb->offset;
        nb += ioo->ioo_bufcnt - 1;
        opd.opd_extent.end = nb->offset + nb->len - 1;
        opd.opd_timeout = prolong_timeout(req);

	DEBUG_REQ(D_RPCTRACE, req,
	       "%s %s: refresh rw locks: " LPU64"/"LPU64" ("LPU64"->"LPU64")\n",
	       obd->obd_name, current->comm,
	       opd.opd_resid.name[0], opd.opd_resid.name[1],
	       opd.opd_extent.start, opd.opd_extent.end);

        ost_prolong_locks(&opd);

        CDEBUG(D_DLMTRACE, "%s: refreshed %u locks timeout for req %p.\n",
               obd->obd_name, opd.opd_locks, req);

        RETURN(opd.opd_locks > 0);
}

static void ost_rw_hpreq_fini(struct ptlrpc_request *req)
{
        (void)ost_rw_hpreq_check(req);
}

/**
 * Like ost_rw_hpreq_lock_match(), but for OST_PUNCH RPCs.
 */
static int ost_punch_hpreq_lock_match(struct ptlrpc_request *req,
                                      struct ldlm_lock *lock)
{
        struct ost_body *body;
        ENTRY;

        body = req_capsule_client_get(&req->rq_pill, &RMF_OST_BODY);
        LASSERT(body != NULL);

        if (body->oa.o_valid & OBD_MD_FLHANDLE &&
            body->oa.o_handle.cookie == lock->l_handle.h_cookie)
                RETURN(1);

        RETURN(0);
}

/**
 * Like ost_rw_hpreq_check(), but for OST_PUNCH RPCs.
 */
static int ost_punch_hpreq_check(struct ptlrpc_request *req)
{
        struct obd_device *obd = req->rq_export->exp_obd;
        struct ost_body *body;
        struct obdo *oa;
        struct ost_prolong_data opd = { 0 };
        __u64 start, end;
        ENTRY;

        body = req_capsule_client_get(&req->rq_pill, &RMF_OST_BODY);
        LASSERT(body != NULL);

        oa = &body->oa;
        LASSERT(!(oa->o_valid & OBD_MD_FLFLAGS) ||
                !(oa->o_flags & OBD_FL_SRVLOCK));

        start = oa->o_size;
        end = start + oa->o_blocks;

        opd.opd_req = req;
        opd.opd_mode = LCK_PW;
        opd.opd_exp = req->rq_export;
        opd.opd_oa  = oa;
        opd.opd_extent.start = start;
        opd.opd_extent.end   = end;
        if (oa->o_blocks == OBD_OBJECT_EOF)
                opd.opd_extent.end = OBD_OBJECT_EOF;
        opd.opd_timeout = prolong_timeout(req);

	ostid_build_res_name(&oa->o_oi, &opd.opd_resid);

        CDEBUG(D_DLMTRACE,
               "%s: refresh locks: "LPU64"/"LPU64" ("LPU64"->"LPU64")\n",
               obd->obd_name,
               opd.opd_resid.name[0], opd.opd_resid.name[1],
               opd.opd_extent.start, opd.opd_extent.end);

        ost_prolong_locks(&opd);

        CDEBUG(D_DLMTRACE, "%s: refreshed %u locks timeout for req %p.\n",
               obd->obd_name, opd.opd_locks, req);

        RETURN(opd.opd_locks > 0);
}

static void ost_punch_hpreq_fini(struct ptlrpc_request *req)
{
        (void)ost_punch_hpreq_check(req);
}

struct ptlrpc_hpreq_ops ost_hpreq_rw = {
        .hpreq_lock_match = ost_rw_hpreq_lock_match,
        .hpreq_check      = ost_rw_hpreq_check,
        .hpreq_fini       = ost_rw_hpreq_fini
};

struct ptlrpc_hpreq_ops ost_hpreq_punch = {
        .hpreq_lock_match = ost_punch_hpreq_lock_match,
        .hpreq_check      = ost_punch_hpreq_check,
        .hpreq_fini       = ost_punch_hpreq_fini
};

/** Assign high priority operations to the request if needed. */
static int ost_io_hpreq_handler(struct ptlrpc_request *req)
{
        ENTRY;
        if (req->rq_export) {
                int opc = lustre_msg_get_opc(req->rq_reqmsg);
                struct ost_body *body;

                if (opc == OST_READ || opc == OST_WRITE) {
                        struct niobuf_remote *nb;
                        struct obd_ioobj *ioo;
                        int objcount, niocount;
                        int rc;
                        int i;

                        /* RPCs on the H-P queue can be inspected before
                         * ost_handler() initializes their pills, so we
                         * initialize that here.  Capsule initialization is
                         * idempotent, as is setting the pill's format (provided
                         * it doesn't change).
                         */
                        req_capsule_init(&req->rq_pill, req, RCL_SERVER);
                        if (opc == OST_READ)
                                req_capsule_set(&req->rq_pill,
                                                &RQF_OST_BRW_READ);
                        else
                                req_capsule_set(&req->rq_pill,
                                                &RQF_OST_BRW_WRITE);

                        body = req_capsule_client_get(&req->rq_pill,
                                                      &RMF_OST_BODY);
                        if (body == NULL) {
                                CERROR("Missing/short ost_body\n");
                                RETURN(-EFAULT);
                        }

                        objcount = req_capsule_get_size(&req->rq_pill,
                                                        &RMF_OBD_IOOBJ,
                                                        RCL_CLIENT) /
                                                        sizeof(*ioo);
                        if (objcount == 0) {
                                CERROR("Missing/short ioobj\n");
                                RETURN(-EFAULT);
                        }
                        if (objcount > 1) {
                                CERROR("too many ioobjs (%d)\n", objcount);
                                RETURN(-EFAULT);
                        }

                        ioo = req_capsule_client_get(&req->rq_pill,
                                                     &RMF_OBD_IOOBJ);
                        if (ioo == NULL) {
                                CERROR("Missing/short ioobj\n");
                                RETURN(-EFAULT);
                        }

                        rc = ost_validate_obdo(req->rq_export, &body->oa, ioo);
                        if (rc) {
                                CERROR("invalid object ids\n");
                                RETURN(rc);
                        }

                        for (niocount = i = 0; i < objcount; i++) {
                                if (ioo[i].ioo_bufcnt == 0) {
                                        CERROR("ioo[%d] has zero bufcnt\n", i);
                                        RETURN(-EFAULT);
                                }
                                niocount += ioo[i].ioo_bufcnt;
                        }
                        if (niocount > PTLRPC_MAX_BRW_PAGES) {
                                DEBUG_REQ(D_RPCTRACE, req,
                                          "bulk has too many pages (%d)",
                                          niocount);
                                RETURN(-EFAULT);
                        }

                        nb = req_capsule_client_get(&req->rq_pill,
                                                    &RMF_NIOBUF_REMOTE);
                        if (nb == NULL) {
                                CERROR("Missing/short niobuf\n");
                                RETURN(-EFAULT);
                        }

                        if (niocount == 0 || !(nb[0].flags & OBD_BRW_SRVLOCK))
                                req->rq_ops = &ost_hpreq_rw;
                } else if (opc == OST_PUNCH) {
                        req_capsule_init(&req->rq_pill, req, RCL_SERVER);
                        req_capsule_set(&req->rq_pill, &RQF_OST_PUNCH);

                        body = req_capsule_client_get(&req->rq_pill,
                                                      &RMF_OST_BODY);
                        if (body == NULL) {
                                CERROR("Missing/short ost_body\n");
                                RETURN(-EFAULT);
                        }

                        if (!(body->oa.o_valid & OBD_MD_FLFLAGS) ||
                            !(body->oa.o_flags & OBD_FL_SRVLOCK))
                                req->rq_ops = &ost_hpreq_punch;
                }
        }
        RETURN(0);
}

/* TODO: handle requests in a similar way as MDT: see mdt_handle_common() */
int ost_handle(struct ptlrpc_request *req)
{
	struct obd_trans_info trans_info = { 0, };
	struct obd_trans_info *oti = &trans_info;
	int should_process, fail = OBD_FAIL_OST_ALL_REPLY_NET, rc = 0;
	struct obd_device *obd = NULL;
	__u32 opc = lustre_msg_get_opc(req->rq_reqmsg);
	ENTRY;

	/* OST module is kept between remounts, but the last reference
	 * to specific module (say, osd or ofd) kills all related keys
	 * from the environment. so we have to refill it until the root
	 * cause is fixed properly */
	lu_env_refill(req->rq_svc_thread->t_env);

	LASSERT(current->journal_info == NULL);

	/* primordial rpcs don't affect server recovery */
	switch (opc) {
	case SEC_CTX_INIT:
	case SEC_CTX_INIT_CONT:
	case SEC_CTX_FINI:
		GOTO(out, rc = 0);
	}

	req_capsule_init(&req->rq_pill, req, RCL_SERVER);

	if (opc != OST_CONNECT) {
		if (!class_connected_export(req->rq_export)) {
			CDEBUG(D_HA,"operation %d on unconnected OST from %s\n",
			       opc, libcfs_id2str(req->rq_peer));
                        req->rq_status = -ENOTCONN;
                        GOTO(out, rc = -ENOTCONN);
                }

                obd = req->rq_export->exp_obd;

                /* Check for aborted recovery. */
                if (obd->obd_recovering) {
                        rc = ost_filter_recovery_request(req, obd,
                                                         &should_process);
                        if (rc || !should_process)
                                RETURN(rc);
                        else if (should_process < 0) {
                                req->rq_status = should_process;
                                rc = ptlrpc_error(req);
                                RETURN(rc);
                        }
                }
        }

        oti_init(oti, req);

        rc = ost_msg_check_version(req->rq_reqmsg);
        if (rc)
                RETURN(rc);

	if (req && req->rq_reqmsg && req->rq_export &&
	    (exp_connect_flags(req->rq_export) & OBD_CONNECT_JOBSTATS))
		oti->oti_jobid = lustre_msg_get_jobid(req->rq_reqmsg);

	switch (opc) {
        case OST_CONNECT: {
                CDEBUG(D_INODE, "connect\n");
                req_capsule_set(&req->rq_pill, &RQF_OST_CONNECT);
                if (OBD_FAIL_CHECK(OBD_FAIL_OST_CONNECT_NET))
                        RETURN(0);
                rc = target_handle_connect(req);
                if (OBD_FAIL_CHECK(OBD_FAIL_OST_CONNECT_NET2))
                        RETURN(0);
                if (!rc) {
                        rc = ost_init_sec_level(req);
                        if (!rc)
                                rc = ost_connect_check_sptlrpc(req);
                }
		if (rc == 0) {
			struct obd_export *exp = req->rq_export;
			struct obd_connect_data *reply;
			/* Now that connection handling has completed
			 * successfully, atomically update the connect flags
			 * in the shared export data structure.*/
			reply = req_capsule_server_get(&req->rq_pill,
						       &RMF_CONNECT_DATA);
			spin_lock(&exp->exp_lock);
			exp->exp_connect_data = *reply;
			spin_unlock(&exp->exp_lock);
		}
                break;
        }
        case OST_DISCONNECT:
                CDEBUG(D_INODE, "disconnect\n");
                req_capsule_set(&req->rq_pill, &RQF_OST_DISCONNECT);
                if (OBD_FAIL_CHECK(OBD_FAIL_OST_DISCONNECT_NET))
                        RETURN(0);
                rc = target_handle_disconnect(req);
                break;
        case OST_CREATE:
                CDEBUG(D_INODE, "create\n");
                req_capsule_set(&req->rq_pill, &RQF_OST_CREATE);
                if (OBD_FAIL_CHECK(OBD_FAIL_OST_CREATE_NET))
                        RETURN(0);
                if (OBD_FAIL_CHECK(OBD_FAIL_OST_EROFS))
                        GOTO(out, rc = -EROFS);
                rc = ost_create(req->rq_export, req, oti);
                break;
        case OST_DESTROY:
                CDEBUG(D_INODE, "destroy\n");
                req_capsule_set(&req->rq_pill, &RQF_OST_DESTROY);
                if (OBD_FAIL_CHECK(OBD_FAIL_OST_DESTROY_NET))
                        RETURN(0);
                if (OBD_FAIL_CHECK(OBD_FAIL_OST_EROFS))
                        GOTO(out, rc = -EROFS);
                rc = ost_destroy(req->rq_export, req, oti);
                break;
        case OST_GETATTR:
                CDEBUG(D_INODE, "getattr\n");
                req_capsule_set(&req->rq_pill, &RQF_OST_GETATTR);
                if (OBD_FAIL_CHECK(OBD_FAIL_OST_GETATTR_NET))
                        RETURN(0);
                rc = ost_getattr(req->rq_export, req);
                break;
        case OST_SETATTR:
                CDEBUG(D_INODE, "setattr\n");
                req_capsule_set(&req->rq_pill, &RQF_OST_SETATTR);
                if (OBD_FAIL_CHECK(OBD_FAIL_OST_SETATTR_NET))
                        RETURN(0);
                rc = ost_setattr(req->rq_export, req, oti);
                break;
        case OST_WRITE:
                req_capsule_set(&req->rq_pill, &RQF_OST_BRW_WRITE);
                CDEBUG(D_INODE, "write\n");
                /* req->rq_request_portal would be nice, if it was set */
		if (ptlrpc_req2svc(req)->srv_req_portal != OST_IO_PORTAL) {
			CERROR("%s: deny write request from %s to portal %u\n",
			       req->rq_export->exp_obd->obd_name,
			       obd_export_nid2str(req->rq_export),
			       ptlrpc_req2svc(req)->srv_req_portal);
                        GOTO(out, rc = -EPROTO);
                }
                if (OBD_FAIL_CHECK(OBD_FAIL_OST_BRW_NET))
                        RETURN(0);
                if (OBD_FAIL_CHECK(OBD_FAIL_OST_ENOSPC))
                        GOTO(out, rc = -ENOSPC);
                if (OBD_FAIL_TIMEOUT(OBD_FAIL_OST_EROFS, 1))
                        GOTO(out, rc = -EROFS);
                rc = ost_brw_write(req, oti);
                LASSERT(current->journal_info == NULL);
                /* ost_brw_write sends its own replies */
                RETURN(rc);
        case OST_READ:
                req_capsule_set(&req->rq_pill, &RQF_OST_BRW_READ);
                CDEBUG(D_INODE, "read\n");
                /* req->rq_request_portal would be nice, if it was set */
		if (ptlrpc_req2svc(req)->srv_req_portal != OST_IO_PORTAL) {
			CERROR("%s: deny read request from %s to portal %u\n",
			       req->rq_export->exp_obd->obd_name,
			       obd_export_nid2str(req->rq_export),
			       ptlrpc_req2svc(req)->srv_req_portal);
                        GOTO(out, rc = -EPROTO);
                }
                if (OBD_FAIL_CHECK(OBD_FAIL_OST_BRW_NET))
                        RETURN(0);
                rc = ost_brw_read(req, oti);
                LASSERT(current->journal_info == NULL);
                /* ost_brw_read sends its own replies */
                RETURN(rc);
        case OST_PUNCH:
                CDEBUG(D_INODE, "punch\n");
                req_capsule_set(&req->rq_pill, &RQF_OST_PUNCH);
                if (OBD_FAIL_CHECK(OBD_FAIL_OST_PUNCH_NET))
                        RETURN(0);
                if (OBD_FAIL_CHECK(OBD_FAIL_OST_EROFS))
                        GOTO(out, rc = -EROFS);
                rc = ost_punch(req->rq_export, req, oti);
                break;
        case OST_STATFS:
                CDEBUG(D_INODE, "statfs\n");
                req_capsule_set(&req->rq_pill, &RQF_OST_STATFS);
                if (OBD_FAIL_CHECK(OBD_FAIL_OST_STATFS_NET))
                        RETURN(0);
                rc = ost_statfs(req);
                break;
        case OST_SYNC:
                CDEBUG(D_INODE, "sync\n");
                req_capsule_set(&req->rq_pill, &RQF_OST_SYNC);
                if (OBD_FAIL_CHECK(OBD_FAIL_OST_SYNC_NET))
                        RETURN(0);
		rc = ost_sync(req->rq_export, req, oti);
                break;
        case OST_SET_INFO:
                DEBUG_REQ(D_INODE, req, "set_info");
                req_capsule_set(&req->rq_pill, &RQF_OBD_SET_INFO);
                rc = ost_set_info(req->rq_export, req);
                break;
        case OST_GET_INFO:
                DEBUG_REQ(D_INODE, req, "get_info");
                req_capsule_set(&req->rq_pill, &RQF_OST_GET_INFO_GENERIC);
                rc = ost_get_info(req->rq_export, req);
                break;
        case OST_QUOTACHECK:
                CDEBUG(D_INODE, "quotacheck\n");
                req_capsule_set(&req->rq_pill, &RQF_OST_QUOTACHECK);
                if (OBD_FAIL_CHECK(OBD_FAIL_OST_QUOTACHECK_NET))
                        RETURN(0);
                rc = ost_handle_quotacheck(req);
                break;
        case OST_QUOTACTL:
                CDEBUG(D_INODE, "quotactl\n");
                req_capsule_set(&req->rq_pill, &RQF_OST_QUOTACTL);
                if (OBD_FAIL_CHECK(OBD_FAIL_OST_QUOTACTL_NET))
                        RETURN(0);
                rc = ost_handle_quotactl(req);
                break;
        case OBD_PING:
                DEBUG_REQ(D_INODE, req, "ping");
                req_capsule_set(&req->rq_pill, &RQF_OBD_PING);
                rc = target_handle_ping(req);
                break;
        /* FIXME - just reply status */
        case LLOG_ORIGIN_CONNECT:
                DEBUG_REQ(D_INODE, req, "log connect");
                req_capsule_set(&req->rq_pill, &RQF_LLOG_ORIGIN_CONNECT);
                rc = ost_llog_handle_connect(req->rq_export, req);
                req->rq_status = rc;
                rc = req_capsule_server_pack(&req->rq_pill);
                if (rc)
                        RETURN(rc);
                RETURN(ptlrpc_reply(req));
	case LDLM_ENQUEUE:
		CDEBUG(D_INODE, "enqueue\n");
		req_capsule_set(&req->rq_pill, &RQF_LDLM_ENQUEUE);
		if (OBD_FAIL_CHECK(OBD_FAIL_LDLM_ENQUEUE_NET))
			RETURN(0);
		rc = ldlm_handle_enqueue(req, ldlm_server_completion_ast,
					 ost_blocking_ast,
					 ldlm_server_glimpse_ast);
		fail = OBD_FAIL_OST_LDLM_REPLY_NET;
		break;
	case LDLM_CONVERT:
		CDEBUG(D_INODE, "convert\n");
		req_capsule_set(&req->rq_pill, &RQF_LDLM_CONVERT);
		if (OBD_FAIL_CHECK(OBD_FAIL_LDLM_CONVERT_NET))
			RETURN(0);
		rc = ldlm_handle_convert(req);
		break;
	case LDLM_CANCEL:
		CDEBUG(D_INODE, "cancel\n");
		req_capsule_set(&req->rq_pill, &RQF_LDLM_CANCEL);
		if (OBD_FAIL_CHECK(OBD_FAIL_LDLM_CANCEL_NET))
			RETURN(0);
		rc = ldlm_handle_cancel(req);
		break;
        case LDLM_BL_CALLBACK:
        case LDLM_CP_CALLBACK:
                CDEBUG(D_INODE, "callback\n");
                CERROR("callbacks should not happen on OST\n");
                /* fall through */
        default:
		CERROR("Unexpected opcode %d\n", opc);
                req->rq_status = -ENOTSUPP;
                rc = ptlrpc_error(req);
                RETURN(rc);
        }

        LASSERT(current->journal_info == NULL);

        EXIT;
        /* If we're DISCONNECTing, the export_data is already freed */
	if (!rc && opc != OST_DISCONNECT)
                target_committed_to_req(req);

out:
        if (!rc)
                oti_to_request(oti, req);

        target_send_reply(req, rc, fail);
        return 0;
}
EXPORT_SYMBOL(ost_handle);

/*
 * free per-thread pool created by ost_io_thread_init().
 */
static void ost_io_thread_done(struct ptlrpc_thread *thread)
{
        struct ost_thread_local_cache *tls; /* TLS stands for Thread-Local
                                             * Storage */

        ENTRY;

        LASSERT(thread != NULL);

        /*
         * be prepared to handle partially-initialized pools (because this is
         * called from ost_io_thread_init() for cleanup.
         */
        tls = thread->t_data;
        if (tls != NULL) {
                OBD_FREE_PTR(tls);
                thread->t_data = NULL;
        }
        EXIT;
}

/*
 * initialize per-thread page pool (bug 5137).
 */
static int ost_io_thread_init(struct ptlrpc_thread *thread)
{
        struct ost_thread_local_cache *tls;

        ENTRY;

        LASSERT(thread != NULL);
        LASSERT(thread->t_data == NULL);

        OBD_ALLOC_PTR(tls);
        if (tls == NULL)
                RETURN(-ENOMEM);
        thread->t_data = tls;
        RETURN(0);
}

#define OST_WATCHDOG_TIMEOUT (obd_timeout * 1000)

static struct cfs_cpt_table	*ost_io_cptable;

/* Sigh - really, this is an OSS, the _server_, not the _target_ */
static int ost_setup(struct obd_device *obd, struct lustre_cfg* lcfg)
{
	static struct ptlrpc_service_conf	svc_conf;
	struct ost_obd *ost = &obd->u.ost;
	struct lprocfs_static_vars lvars;
	nodemask_t		*mask;
	int rc;
	ENTRY;

        rc = cfs_cleanup_group_info();
        if (rc)
                RETURN(rc);

        lprocfs_ost_init_vars(&lvars);
        lprocfs_obd_setup(obd, lvars.obd_vars);

	mutex_init(&ost->ost_health_mutex);

	svc_conf = (typeof(svc_conf)) {
		.psc_name		= LUSTRE_OSS_NAME,
		.psc_watchdog_factor	= OSS_SERVICE_WATCHDOG_FACTOR,
		.psc_buf		= {
			.bc_nbufs		= OST_NBUFS,
			.bc_buf_size		= OST_BUFSIZE,
			.bc_req_max_size	= OST_MAXREQSIZE,
			.bc_rep_max_size	= OST_MAXREPSIZE,
			.bc_req_portal		= OST_REQUEST_PORTAL,
			.bc_rep_portal		= OSC_REPLY_PORTAL,
		},
		.psc_thr		= {
			.tc_thr_name		= "ll_ost",
			.tc_thr_factor		= OSS_THR_FACTOR,
			.tc_nthrs_init		= OSS_NTHRS_INIT,
			.tc_nthrs_base		= OSS_NTHRS_BASE,
			.tc_nthrs_max		= OSS_NTHRS_MAX,
			.tc_nthrs_user		= oss_num_threads,
			.tc_cpu_affinity	= 1,
			.tc_ctx_tags		= LCT_DT_THREAD,
		},
		.psc_cpt                = {
			.cc_pattern             = oss_cpts,
		},
		.psc_ops		= {
			.so_req_handler		= ost_handle,
			.so_req_printer		= target_print_req,
			.so_hpreq_handler	= ptlrpc_hpreq_handler,
		},
	};
	ost->ost_service = ptlrpc_register_service(&svc_conf,
						   obd->obd_proc_entry);
	if (IS_ERR(ost->ost_service)) {
		rc = PTR_ERR(ost->ost_service);
		CERROR("failed to start service: %d\n", rc);
		GOTO(out_lprocfs, rc);
        }

	memset(&svc_conf, 0, sizeof(svc_conf));
	svc_conf = (typeof(svc_conf)) {
		.psc_name		= "ost_create",
		.psc_watchdog_factor	= OSS_SERVICE_WATCHDOG_FACTOR,
		.psc_buf		= {
			.bc_nbufs		= OST_NBUFS,
			.bc_buf_size		= OST_BUFSIZE,
			.bc_req_max_size	= OST_MAXREQSIZE,
			.bc_rep_max_size	= OST_MAXREPSIZE,
			.bc_req_portal		= OST_CREATE_PORTAL,
			.bc_rep_portal		= OSC_REPLY_PORTAL,
		},
		.psc_thr		= {
			.tc_thr_name		= "ll_ost_create",
			.tc_thr_factor		= OSS_CR_THR_FACTOR,
			.tc_nthrs_init		= OSS_CR_NTHRS_INIT,
			.tc_nthrs_base		= OSS_CR_NTHRS_BASE,
			.tc_nthrs_max		= OSS_CR_NTHRS_MAX,
			.tc_nthrs_user		= oss_num_create_threads,
			.tc_cpu_affinity	= 1,
			.tc_ctx_tags		= LCT_DT_THREAD,
		},
		.psc_cpt                = {
			.cc_pattern             = oss_cpts,
		},
		.psc_ops		= {
			.so_req_handler		= ost_handle,
			.so_req_printer		= target_print_req,
		},
	};
	ost->ost_create_service = ptlrpc_register_service(&svc_conf,
							  obd->obd_proc_entry);
	if (IS_ERR(ost->ost_create_service)) {
		rc = PTR_ERR(ost->ost_create_service);
		CERROR("failed to start OST create service: %d\n", rc);
		GOTO(out_service, rc);
        }

	mask = cfs_cpt_table->ctb_nodemask;
	/* event CPT feature is disabled in libcfs level by set partition
	 * number to 1, we still want to set node affinity for io service */
	if (cfs_cpt_number(cfs_cpt_table) == 1 && nodes_weight(*mask) > 1) {
		int	cpt = 0;
		int	i;

		ost_io_cptable = cfs_cpt_table_alloc(nodes_weight(*mask));
		for_each_node_mask(i, *mask) {
			if (ost_io_cptable == NULL) {
				CWARN("OSS failed to create CPT table\n");
				break;
			}

			rc = cfs_cpt_set_node(ost_io_cptable, cpt++, i);
			if (!rc) {
				CWARN("OSS Failed to set node %d for"
				      "IO CPT table\n", i);
				cfs_cpt_table_free(ost_io_cptable);
				ost_io_cptable = NULL;
				break;
			}
		}
	}

	memset(&svc_conf, 0, sizeof(svc_conf));
	svc_conf = (typeof(svc_conf)) {
		.psc_name		= "ost_io",
		.psc_watchdog_factor	= OSS_SERVICE_WATCHDOG_FACTOR,
		.psc_buf		= {
			.bc_nbufs		= OST_NBUFS,
			.bc_buf_size		= OST_IO_BUFSIZE,
			.bc_req_max_size	= OST_IO_MAXREQSIZE,
			.bc_rep_max_size	= OST_IO_MAXREPSIZE,
			.bc_req_portal		= OST_IO_PORTAL,
			.bc_rep_portal		= OSC_REPLY_PORTAL,
		},
		.psc_thr		= {
			.tc_thr_name		= "ll_ost_io",
			.tc_thr_factor		= OSS_THR_FACTOR,
			.tc_nthrs_init		= OSS_NTHRS_INIT,
			.tc_nthrs_base		= OSS_NTHRS_BASE,
			.tc_nthrs_max		= OSS_NTHRS_MAX,
			.tc_nthrs_user		= oss_num_threads,
			.tc_cpu_affinity	= 1,
			.tc_ctx_tags		= LCT_DT_THREAD,
		},
		.psc_cpt		= {
			.cc_cptable		= ost_io_cptable,
			.cc_pattern		= ost_io_cptable == NULL ?
						  oss_io_cpts : NULL,
		},
		.psc_ops		= {
			.so_thr_init		= ost_io_thread_init,
			.so_thr_done		= ost_io_thread_done,
			.so_req_handler		= ost_handle,
			.so_hpreq_handler	= ost_io_hpreq_handler,
			.so_req_printer		= target_print_req,
		},
	};
	ost->ost_io_service = ptlrpc_register_service(&svc_conf,
						      obd->obd_proc_entry);
	if (IS_ERR(ost->ost_io_service)) {
		rc = PTR_ERR(ost->ost_io_service);
		CERROR("failed to start OST I/O service: %d\n", rc);
		ost->ost_io_service = NULL;
		GOTO(out_create, rc);
        }

	memset(&svc_conf, 0, sizeof(svc_conf));
	svc_conf = (typeof(svc_conf)) {
		.psc_name		= "ost_seq",
		.psc_watchdog_factor	= OSS_SERVICE_WATCHDOG_FACTOR,
		.psc_buf		= {
			.bc_nbufs		= OST_NBUFS,
			.bc_buf_size		= OST_BUFSIZE,
			.bc_req_max_size	= OST_MAXREQSIZE,
			.bc_rep_max_size	= OST_MAXREPSIZE,
			.bc_req_portal		= SEQ_DATA_PORTAL,
			.bc_rep_portal		= OSC_REPLY_PORTAL,
		},
		.psc_thr		= {
			.tc_thr_name		= "ll_ost_seq",
			.tc_thr_factor		= OSS_CR_THR_FACTOR,
			.tc_nthrs_init		= OSS_CR_NTHRS_INIT,
			.tc_nthrs_base		= OSS_CR_NTHRS_BASE,
			.tc_nthrs_max		= OSS_CR_NTHRS_MAX,
			.tc_nthrs_user		= oss_num_create_threads,
			.tc_cpu_affinity	= 1,
			.tc_ctx_tags		= LCT_DT_THREAD,
		},

		.psc_cpt		= {
			.cc_pattern	     = oss_cpts,
		},
		.psc_ops		= {
			.so_req_handler		= tgt_request_handle,
			.so_req_printer		= target_print_req,
			.so_hpreq_handler	= NULL,
		},
	};
	ost->ost_seq_service = ptlrpc_register_service(&svc_conf,
						      obd->obd_proc_entry);
	if (IS_ERR(ost->ost_seq_service)) {
		rc = PTR_ERR(ost->ost_seq_service);
		CERROR("failed to start OST seq service: %d\n", rc);
		ost->ost_seq_service = NULL;
		GOTO(out_io, rc);
	}

#if 0
	/* Object update service */
	memset(&svc_conf, 0, sizeof(svc_conf));
	svc_conf = (typeof(svc_conf)) {
		.psc_name		= "ost_out",
		.psc_watchdog_factor	= OSS_SERVICE_WATCHDOG_FACTOR,
		.psc_buf		= {
			.bc_nbufs		= OST_NBUFS,
			.bc_buf_size		= OUT_BUFSIZE,
			.bc_req_max_size	= OUT_MAXREQSIZE,
			.bc_rep_max_size	= OUT_MAXREPSIZE,
			.bc_req_portal		= OUT_PORTAL,
			.bc_rep_portal		= OSC_REPLY_PORTAL,
		},
		/*
		 * We'd like to have a mechanism to set this on a per-device
		 * basis, but alas...
		 */
		.psc_thr		= {
			.tc_thr_name		= "ll_ost_out",
			.tc_thr_factor		= OSS_CR_THR_FACTOR,
			.tc_nthrs_init		= OSS_CR_NTHRS_INIT,
			.tc_nthrs_base		= OSS_CR_NTHRS_BASE,
			.tc_nthrs_max		= OSS_CR_NTHRS_MAX,
			.tc_nthrs_user		= oss_num_create_threads,
			.tc_cpu_affinity	= 1,
			.tc_ctx_tags		= LCT_DT_THREAD,
		},
		.psc_cpt		= {
			.cc_pattern		= oss_cpts,
		},
		.psc_ops		= {
			.so_req_handler		= tgt_request_handle,
			.so_req_printer		= target_print_req,
			.so_hpreq_handler	= NULL,
		},
	};
	ost->ost_out_service = ptlrpc_register_service(&svc_conf,
						       obd->obd_proc_entry);
	if (IS_ERR(ost->ost_out_service)) {
		rc = PTR_ERR(ost->ost_out_service);
		CERROR("failed to start out service: %d\n", rc);
		ost->ost_out_service = NULL;
		GOTO(out_seq, rc);
	}
#endif
	ping_evictor_start();

	RETURN(0);
out_io:
	ptlrpc_unregister_service(ost->ost_io_service);
	ost->ost_io_service = NULL;
out_create:
        ptlrpc_unregister_service(ost->ost_create_service);
        ost->ost_create_service = NULL;
out_service:
        ptlrpc_unregister_service(ost->ost_service);
        ost->ost_service = NULL;
out_lprocfs:
        lprocfs_obd_cleanup(obd);
        RETURN(rc);
}

static int ost_cleanup(struct obd_device *obd)
{
	struct ost_obd *ost = &obd->u.ost;
	int err = 0;
	ENTRY;

	ping_evictor_stop();

	/* there is no recovery for OST OBD, all recovery is controlled by
	 * obdfilter OBD */
	LASSERT(obd->obd_recovering == 0);
	mutex_lock(&ost->ost_health_mutex);
	ptlrpc_unregister_service(ost->ost_service);
	ptlrpc_unregister_service(ost->ost_create_service);
	ptlrpc_unregister_service(ost->ost_io_service);
	ptlrpc_unregister_service(ost->ost_seq_service);
#if 0
	ptlrpc_unregister_service(ost->ost_out_service);
#endif
	ost->ost_service = NULL;
	ost->ost_create_service = NULL;
	ost->ost_io_service = NULL;
	ost->ost_seq_service = NULL;
	ost->ost_out_service = NULL;

	mutex_unlock(&ost->ost_health_mutex);

	lprocfs_obd_cleanup(obd);

	if (ost_io_cptable != NULL) {
		cfs_cpt_table_free(ost_io_cptable);
		ost_io_cptable = NULL;
	}

	RETURN(err);
}

static int ost_health_check(const struct lu_env *env, struct obd_device *obd)
{
        struct ost_obd *ost = &obd->u.ost;
        int rc = 0;

	mutex_lock(&ost->ost_health_mutex);
        rc |= ptlrpc_service_health_check(ost->ost_service);
        rc |= ptlrpc_service_health_check(ost->ost_create_service);
        rc |= ptlrpc_service_health_check(ost->ost_io_service);
	mutex_unlock(&ost->ost_health_mutex);

        /*
         * health_check to return 0 on healthy
         * and 1 on unhealthy.
         */
        if( rc != 0)
                rc = 1;

        return rc;
}

struct ost_thread_local_cache *ost_tls(struct ptlrpc_request *r)
{
        return (struct ost_thread_local_cache *)(r->rq_svc_thread->t_data);
}

/* use obd ops to offer management infrastructure */
static struct obd_ops ost_obd_ops = {
        .o_owner        = THIS_MODULE,
        .o_setup        = ost_setup,
        .o_cleanup      = ost_cleanup,
        .o_health_check = ost_health_check,
};


static int __init ost_init(void)
{
        struct lprocfs_static_vars lvars;
        int rc;
        ENTRY;

	ost_page_to_corrupt = alloc_page(GFP_IOFS);

        lprocfs_ost_init_vars(&lvars);
        rc = class_register_type(&ost_obd_ops, NULL, lvars.module_vars,
                                 LUSTRE_OSS_NAME, NULL);

        if (ost_num_threads != 0 && oss_num_threads == 0) {
                LCONSOLE_INFO("ost_num_threads module parameter is deprecated, "
                              "use oss_num_threads instead or unset both for "
                              "dynamic thread startup\n");
                oss_num_threads = ost_num_threads;
        }

        RETURN(rc);
}

static void /*__exit*/ ost_exit(void)
{
	if (ost_page_to_corrupt)
		page_cache_release(ost_page_to_corrupt);

        class_unregister_type(LUSTRE_OSS_NAME);
}

MODULE_AUTHOR("Sun Microsystems, Inc. <http://www.lustre.org/>");
MODULE_DESCRIPTION("Lustre Object Storage Target (OST) v0.01");
MODULE_LICENSE("GPL");

module_init(ost_init);
module_exit(ost_exit);
