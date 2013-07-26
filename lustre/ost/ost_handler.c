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
#include <obd_ost.h>
#include <lustre_dlm.h>
#include <lprocfs_status.h>
#include "ost_internal.h"

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

        mode = LCK_PW;
        if (opc == OST_READ)
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
			.so_req_handler		= tgt_request_handle,
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
			.so_req_handler		= tgt_request_handle,
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
			.so_thr_init		= tgt_io_thread_init,
			.so_thr_done		= tgt_io_thread_done,
			.so_req_handler		= tgt_request_handle,
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

	ping_evictor_start();

	RETURN(0);
out_seq:
	ptlrpc_unregister_service(ost->ost_seq_service);
	ost->ost_seq_service = NULL;
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
	ptlrpc_unregister_service(ost->ost_out_service);

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
	class_unregister_type(LUSTRE_OSS_NAME);
}

MODULE_AUTHOR("Sun Microsystems, Inc. <http://www.lustre.org/>");
MODULE_DESCRIPTION("Lustre Object Storage Target (OST) v0.01");
MODULE_LICENSE("GPL");

module_init(ost_init);
module_exit(ost_exit);
