/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
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

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_OST

#include <linux/module.h>
#include <obd_cksum.h>
#include <obd_ost.h>
#include <lustre_net.h>
#include <lustre_dlm.h>
#include <lustre_export.h>
#include <lustre_debug.h>
#include <linux/init.h>
#include <lprocfs_status.h>
#include <libcfs/list.h>
#include <lustre_quota.h>
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
 * 1. If the request comes from 1.8 clients, it will reset o_seq with MDT0.
 * 2. If the request comes from 2.0 clients, currently only RSVD seq and IDIF
 *    req are valid.
 *      a. for single MDS  seq = FID_SEQ_OST_MDT0,
 *      b. for CMD, seq = FID_SEQ_OST_MDT0, FID_SEQ_OST_MDT1 - FID_SEQ_OST_MAX
 */
static int ost_validate_obdo(struct obd_export *exp, struct obdo *oa,
                             struct obd_ioobj *ioobj)
{
        if (oa != NULL && (!(oa->o_valid & OBD_MD_FLGROUP) ||
            !(exp->exp_connect_flags & OBD_CONNECT_FULL20))) {
                oa->o_seq = FID_SEQ_OST_MDT0;
                if (ioobj)
                        ioobj->ioo_seq = FID_SEQ_OST_MDT0;
        /* remove fid_seq_is_rsvd() after FID-on-OST allows SEQ > 9 */
        } else if (oa == NULL ||
                   !(fid_seq_is_rsvd(oa->o_seq) || fid_seq_is_idif(oa->o_seq))) {
                CERROR("%s: client %s sent invalid object "POSTID"\n",
                       exp->exp_obd->obd_name, obd_export_nid2str(exp),
                       oa ? oa->o_id : -1, oa ? oa->o_seq : -1);
                return -EPROTO;
        }
        obdo_from_ostid(oa, &oa->o_oi);
        if (ioobj)
                ioobj_from_obdo(ioobj, oa);
        return 0;
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

        if (body->oa.o_id == 0)
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
        req->rq_status = obd_destroy(exp, &body->oa, NULL, oti, NULL, capa);
        RETURN(0);
}

/**
 * Helper function for getting server side [start, start+count] DLM lock
 * if asked by client.
 */
static int ost_lock_get(struct obd_export *exp, struct obdo *oa,
                        __u64 start, __u64 count, struct lustre_handle *lh,
                        int mode, int flags)
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

        osc_build_res_name(oa->o_id, oa->o_seq, &res_id);
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
                                      ldlm_glimpse_ast, NULL, 0, NULL, lh));
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
        int rc;
        ENTRY;

        body = req_capsule_client_get(&req->rq_pill, &RMF_OST_BODY);
        if (body == NULL)
                RETURN(-EFAULT);

        rc = ost_validate_obdo(exp, &body->oa, NULL);
        if (rc)
                RETURN(rc);

        rc = req_capsule_server_pack(&req->rq_pill);
        if (rc)
                RETURN(rc);

        rc = ost_lock_get(exp, &body->oa, 0, OBD_OBJECT_EOF, &lh, LCK_PR, 0);
        if (rc)
                RETURN(rc);

        if (body->oa.o_valid & OBD_MD_FLOSSCAPA) {
                capa = req_capsule_client_get(&req->rq_pill, &RMF_CAPA1);
                if (capa == NULL) {
                        CERROR("Missing capability for OST GETATTR");
                        GOTO(unlock, rc = -EFAULT);
                }
        }

        OBD_ALLOC_PTR(oinfo);
        if (!oinfo)
                GOTO(unlock, rc = -ENOMEM);
        oinfo->oi_oa = &body->oa;
        oinfo->oi_capa = capa;

        req->rq_status = obd_getattr(exp, oinfo);

        OBD_FREE_PTR(oinfo);

        repbody = req_capsule_server_get(&req->rq_pill, &RMF_OST_BODY);
        repbody->oa = body->oa;
        ost_drop_id(exp, &repbody->oa);

unlock:
        ost_lock_put(exp, &lh, LCK_PR);

        RETURN(0);
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

        req->rq_status = obd_statfs(req->rq_export->exp_obd, osfs,
                                    cfs_time_shift_64(-OBD_STATFS_CACHE_SECONDS),
                                    0);
        if (req->rq_status != 0)
                CERROR("ost: statfs failed: rc %d\n", req->rq_status);

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

        req->rq_status = obd_create(exp, &repbody->oa, NULL, oti);
        //obd_log_cancel(conn, NULL, 1, oti->oti_logcookies, 0);
        RETURN(0);
}

static int ost_punch(struct obd_export *exp, struct ptlrpc_request *req,
                     struct obd_trans_info *oti)
{
        struct ost_body *body, *repbody;
        int rc, flags = 0;
        struct lustre_handle lh = {0,};
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
                flags |= LDLM_AST_DISCARD_DATA;

        rc = ost_lock_get(exp, &body->oa, body->oa.o_size, body->oa.o_blocks,
                          &lh, LCK_PW, flags);
        if (rc == 0) {
                struct obd_info *oinfo;
                struct lustre_capa *capa = NULL;

                if (body->oa.o_valid & OBD_MD_FLFLAGS &&
                    body->oa.o_flags == OBD_FL_SRVLOCK)
                        /*
                         * If OBD_FL_SRVLOCK is the only bit set in
                         * ->o_flags, clear OBD_MD_FLFLAGS to avoid falling
                         * through filter_setattr() to filter_iocontrol().
                         */
                        body->oa.o_valid &= ~OBD_MD_FLFLAGS;

                if (body->oa.o_valid & OBD_MD_FLOSSCAPA) {
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
                oinfo->oi_oa = &body->oa;
                oinfo->oi_policy.l_extent.start = oinfo->oi_oa->o_size;
                oinfo->oi_policy.l_extent.end = oinfo->oi_oa->o_blocks;
                oinfo->oi_capa = capa;

                req->rq_status = obd_punch(exp, oinfo, oti, NULL);
                OBD_FREE_PTR(oinfo);
unlock:
                ost_lock_put(exp, &lh, LCK_PW);
        }

        repbody = req_capsule_server_get(&req->rq_pill, &RMF_OST_BODY);
        repbody->oa = body->oa;
        ost_drop_id(exp, &repbody->oa);
        RETURN(rc);
}

static int ost_sync(struct obd_export *exp, struct ptlrpc_request *req)
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

        OBD_ALLOC_PTR(oinfo);
        if (!oinfo)
                RETURN(-ENOMEM);

        oinfo->oi_oa = &body->oa;
        oinfo->oi_capa = capa;
        req->rq_status = obd_sync(exp, oinfo, body->oa.o_size,
                                  body->oa.o_blocks, NULL);
        OBD_FREE_PTR(oinfo);

        repbody = req_capsule_server_get(&req->rq_pill, &RMF_OST_BODY);
        repbody->oa = body->oa;
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

        OBD_ALLOC_PTR(oinfo);
        if (!oinfo)
                RETURN(-ENOMEM);
        oinfo->oi_oa = &body->oa;
        oinfo->oi_capa = capa;

        req->rq_status = obd_setattr(exp, oinfo, oti);

        OBD_FREE_PTR(oinfo);

        repbody = req_capsule_server_get(&req->rq_pill, &RMF_OST_BODY);
        repbody->oa = body->oa;
        ost_drop_id(exp, &repbody->oa);
        RETURN(0);
}

static __u32 ost_checksum_bulk(struct ptlrpc_bulk_desc *desc, int opc,
                               cksum_type_t cksum_type)
{
        __u32 cksum;
        int i;

        cksum = init_checksum(cksum_type);
        for (i = 0; i < desc->bd_iov_count; i++) {
                struct page *page = desc->bd_iov[i].kiov_page;
                int off = desc->bd_iov[i].kiov_offset & ~CFS_PAGE_MASK;
                char *ptr = kmap(page) + off;
                int len = desc->bd_iov[i].kiov_len;

                /* corrupt the data before we compute the checksum, to
                 * simulate a client->OST data error */
                if (i == 0 && opc == OST_WRITE &&
                    OBD_FAIL_CHECK(OBD_FAIL_OST_CHECKSUM_RECEIVE))
                        memcpy(ptr, "bad3", min(4, len));
                cksum = compute_checksum(cksum, ptr, len, cksum_type);
                /* corrupt the data after we compute the checksum, to
                 * simulate an OST->client data error */
                if (i == 0 && opc == OST_READ &&
                    OBD_FAIL_CHECK(OBD_FAIL_OST_CHECKSUM_SEND)) {
                        memcpy(ptr, "bad4", min(4, len));
                        /* nobody should use corrupted page again */
                        ClearPageUptodate(page);
                }
                kunmap(page);
        }

        return cksum;
}

static int ost_brw_lock_get(int mode, struct obd_export *exp,
                            struct obd_ioobj *obj, struct niobuf_remote *nb,
                            struct lustre_handle *lh)
{
        int flags                 = 0;
        int nrbufs                = obj->ioo_bufcnt;
        struct ldlm_res_id res_id;
        ldlm_policy_data_t policy;
        int i;
        ENTRY;

        osc_build_res_name(obj->ioo_id, obj->ioo_seq, &res_id);
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
                                      ldlm_glimpse_ast, NULL, 0, NULL, lh));
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

struct ost_prolong_data {
        struct obd_export *opd_exp;
        ldlm_policy_data_t opd_policy;
        struct obdo *opd_oa;
        ldlm_mode_t opd_mode;
        int opd_lock_match;
        int opd_timeout;
};

static int ost_prolong_locks_iter(struct ldlm_lock *lock, void *data)
{
        struct ost_prolong_data *opd = data;

        LASSERT(lock->l_resource->lr_type == LDLM_EXTENT);

        if (lock->l_req_mode != lock->l_granted_mode) {
                /* scan granted locks only */
                return LDLM_ITER_STOP;
        }

        if (lock->l_export != opd->opd_exp) {
                /* prolong locks only for given client */
                return LDLM_ITER_CONTINUE;
        }

        if (!(lock->l_granted_mode & opd->opd_mode)) {
                /* we aren't interesting in all type of locks */
                return LDLM_ITER_CONTINUE;
        }

        if (lock->l_policy_data.l_extent.end < opd->opd_policy.l_extent.start ||
            lock->l_policy_data.l_extent.start > opd->opd_policy.l_extent.end) {
                /* the request doesn't cross the lock, skip it */
                return LDLM_ITER_CONTINUE;
        }

        /* Fill the obdo with the matched lock handle.
         * XXX: it is possible in some cases the IO RPC is covered by several
         * locks, even for the write case, so it may need to be a lock list. */
        if (opd->opd_oa && !(opd->opd_oa->o_valid & OBD_MD_FLHANDLE)) {
                opd->opd_oa->o_handle.cookie = lock->l_handle.h_cookie;
                opd->opd_oa->o_valid |= OBD_MD_FLHANDLE;
        }

        if (!(lock->l_flags & LDLM_FL_AST_SENT)) {
                /* ignore locks not being cancelled */
                return LDLM_ITER_CONTINUE;
        }

        CDEBUG(D_DLMTRACE,"refresh lock: "LPU64"/"LPU64" ("LPU64"->"LPU64")\n",
               lock->l_resource->lr_name.name[0],
               lock->l_resource->lr_name.name[1],
               opd->opd_policy.l_extent.start, opd->opd_policy.l_extent.end);
        /* OK. this is a possible lock the user holds doing I/O
         * let's refresh eviction timer for it */
        ldlm_refresh_waiting_lock(lock, opd->opd_timeout);
        opd->opd_lock_match = 1;

        return LDLM_ITER_CONTINUE;
}

static int ost_rw_prolong_locks(struct ptlrpc_request *req, struct obd_ioobj *obj,
                                struct niobuf_remote *nb, struct obdo *oa,
                                ldlm_mode_t mode)
{
        struct ldlm_res_id res_id;
        int nrbufs = obj->ioo_bufcnt;
        struct ost_prolong_data opd = { 0 };
        ENTRY;

        osc_build_res_name(obj->ioo_id, obj->ioo_seq, &res_id);

        opd.opd_mode = mode;
        opd.opd_exp = req->rq_export;
        opd.opd_policy.l_extent.start = nb[0].offset & CFS_PAGE_MASK;
        opd.opd_policy.l_extent.end = (nb[nrbufs - 1].offset +
                                       nb[nrbufs - 1].len - 1) | ~CFS_PAGE_MASK;

        /* prolong locks for the current service time of the corresponding
         * portal (= OST_IO_PORTAL) */
        opd.opd_timeout = AT_OFF ? obd_timeout / 2:
                          max(at_est2timeout(at_get(&req->rq_rqbd->
                              rqbd_service->srv_at_estimate)), ldlm_timeout);

        CDEBUG(D_INFO,"refresh locks: "LPU64"/"LPU64" ("LPU64"->"LPU64")\n",
               res_id.name[0], res_id.name[1], opd.opd_policy.l_extent.start,
               opd.opd_policy.l_extent.end);

        if (oa->o_valid & OBD_MD_FLHANDLE) {
                struct ldlm_lock *lock;

                lock = ldlm_handle2lock(&oa->o_handle);
                if (lock != NULL) {
                        ost_prolong_locks_iter(lock, &opd);
                        if (opd.opd_lock_match) {
                                LDLM_LOCK_PUT(lock);
                                RETURN(1);
                        }

                        /* Check if the lock covers the whole IO region,
                         * otherwise iterate through the resource. */
                        if (lock->l_policy_data.l_extent.end >=
                            opd.opd_policy.l_extent.end &&
                            lock->l_policy_data.l_extent.start <=
                            opd.opd_policy.l_extent.start) {
                                LDLM_LOCK_PUT(lock);
                                RETURN(0);
                        }
                        LDLM_LOCK_PUT(lock);
                }
        }

        opd.opd_oa = oa;
        ldlm_resource_iterate(req->rq_export->exp_obd->obd_namespace, &res_id,
                              ost_prolong_locks_iter, &opd);
        RETURN(opd.opd_lock_match);
}

/* Allocate thread local buffers if needed */
static struct ost_thread_local_cache *ost_tls_get(struct ptlrpc_request *r)
{
        struct ost_thread_local_cache *tls =
                (struct ost_thread_local_cache *)(r->rq_svc_thread->t_data);

        /* In normal mode of operation an I/O request is serviced only
         * by ll_ost_io threads each of them has own tls buffers allocated by
         * ost_thread_init().
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
                       "object "LPX64" took %ld seconds (limit was %ld).\n",
                       libcfs_id2str(req->rq_peer), ioo->ioo_id,
                       cfs_time_current_sec() - req->rq_arrival_time.tv_sec,
                       req->rq_deadline - req->rq_arrival_time.tv_sec);
                GOTO(out_lock, rc = -ETIMEDOUT);
        }

        npages = OST_THREAD_POOL_SIZE;
        rc = obd_preprw(OBD_BRW_READ, exp, &body->oa, 1, ioo,
                        remote_nb, &npages, local_nb, oti, capa);
        if (rc != 0)
                GOTO(out_lock, rc);

        desc = ptlrpc_prep_bulk_exp(req, npages,
                                     BULK_PUT_SOURCE, OST_BULK_PORTAL);
        if (desc == NULL)
                GOTO(out_commitrw, rc = -ENOMEM);

        if (!lustre_handle_is_used(&lockh))
                /* no needs to try to prolong lock if server is asked
                 * to handle locking (= OBD_BRW_SRVLOCK) */
                ost_rw_prolong_locks(req, ioo, remote_nb, &body->oa,
                                     LCK_PW | LCK_PR);

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
                        ptlrpc_prep_bulk_page(desc, local_nb[i].page,
                                              local_nb[i].offset & ~CFS_PAGE_MASK,
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
                cksum_type_t cksum_type = OBD_CKSUM_CRC32;

                if (body->oa.o_valid & OBD_MD_FLFLAGS)
                        cksum_type = cksum_type_unpack(body->oa.o_flags);
                body->oa.o_flags = cksum_type_pack(cksum_type);
                body->oa.o_valid = OBD_MD_FLCKSUM | OBD_MD_FLFLAGS;
                body->oa.o_cksum = ost_checksum_bulk(desc, OST_READ, cksum_type);
                CDEBUG(D_PAGE,"checksum at read origin: %x\n",body->oa.o_cksum);
        } else {
                body->oa.o_valid = 0;
        }
        /* We're finishing using body->oa as an input variable */

        /* Check if client was evicted while we were doing i/o before touching
           network */
        if (rc == 0) {
                rc = target_bulk_io(exp, desc, &lwi);
                no_reply = rc != 0;
        }

out_commitrw:
        /* Must commit after prep above in all cases */
        rc = obd_commitrw(OBD_BRW_READ, exp, &body->oa, 1, ioo,
                          remote_nb, npages, local_nb, oti, rc);

        if (rc == 0) {
                repbody = req_capsule_server_get(&req->rq_pill, &RMF_OST_BODY);
                memcpy(&repbody->oa, &body->oa, sizeof(repbody->oa));
                ost_drop_id(exp, &repbody->oa);
        }

out_lock:
        ost_brw_lock_put(LCK_PR, ioo, remote_nb, &lockh);
out_tls:
        ost_tls_put(req);
out_bulk:
        if (desc)
                ptlrpc_free_bulk(desc);
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
                CWARN("%s: ignoring bulk IO comm error with %s@%s id %s - "
                      "client will retry\n",
                      exp->exp_obd->obd_name,
                      exp->exp_client_uuid.uuid,
                      exp->exp_connection->c_remote_uuid.uuid,
                      libcfs_id2str(req->rq_peer));
        }

        RETURN(rc);
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
                cfs_memory_pressure_set();

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
                       "object "LPX64" took %ld seconds (limit was %ld).\n",
                       libcfs_id2str(req->rq_peer), ioo->ioo_id,
                       cfs_time_current_sec() - req->rq_arrival_time.tv_sec,
                       req->rq_deadline - req->rq_arrival_time.tv_sec);
                GOTO(out_lock, rc = -ETIMEDOUT);
        }

        if (!lustre_handle_is_used(&lockh))
                /* no needs to try to prolong lock if server is asked
                 * to handle locking (= OBD_BRW_SRVLOCK) */
                ost_rw_prolong_locks(req, ioo, remote_nb,&body->oa,  LCK_PW);

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
        npages = OST_THREAD_POOL_SIZE;
        rc = obd_preprw(OBD_BRW_WRITE, exp, &body->oa, objcount,
                        ioo, remote_nb, &npages, local_nb, oti, capa);
        if (rc != 0)
                GOTO(out_lock, rc);

        desc = ptlrpc_prep_bulk_exp(req, npages,
                                     BULK_GET_SINK, OST_BULK_PORTAL);
        if (desc == NULL)
                GOTO(skip_transfer, rc = -ENOMEM);

        /* NB Having prepped, we must commit... */

        for (i = 0; i < npages; i++)
                ptlrpc_prep_bulk_page(desc, local_nb[i].page,
                                      local_nb[i].offset & ~CFS_PAGE_MASK,
                                      local_nb[i].len);

        rc = sptlrpc_svc_prep_bulk(req, desc);
        if (rc != 0)
                GOTO(out_lock, rc);

        rc = target_bulk_io(exp, desc, &lwi);
        no_reply = rc != 0;

skip_transfer:
        repbody = req_capsule_server_get(&req->rq_pill, &RMF_OST_BODY);
        memcpy(&repbody->oa, &body->oa, sizeof(repbody->oa));

        if (unlikely(client_cksum != 0 && rc == 0)) {
                static int cksum_counter;
                repbody->oa.o_valid |= OBD_MD_FLCKSUM | OBD_MD_FLFLAGS;
                repbody->oa.o_flags &= ~OBD_FL_CKSUM_ALL;
                repbody->oa.o_flags |= cksum_type_pack(cksum_type);
                server_cksum = ost_checksum_bulk(desc, OST_WRITE, cksum_type);
                repbody->oa.o_cksum = server_cksum;
                cksum_counter++;
                if (unlikely(client_cksum != server_cksum)) {
                        CDEBUG_LIMIT(mmap ? D_INFO : D_ERROR,
                                     "client csum %x, server csum %x\n",
                                     client_cksum, server_cksum);
                        cksum_counter = 0;
                } else if ((cksum_counter & (-cksum_counter)) == cksum_counter){
                        CDEBUG(D_INFO, "Checksum %u from %s OK: %x\n",
                               cksum_counter, libcfs_id2str(req->rq_peer),
                               server_cksum);
                }
        }

        /* Must commit after prep above in all cases */
        rc = obd_commitrw(OBD_BRW_WRITE, exp, &repbody->oa, objcount, ioo,
                          remote_nb, npages, local_nb, oti, rc);
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

        if (unlikely(client_cksum != server_cksum && rc == 0 &&  !mmap)) {
                int  new_cksum = ost_checksum_bulk(desc, OST_WRITE, cksum_type);
                char *msg;
                char *via;
                char *router;

                if (new_cksum == server_cksum)
                        msg = "changed in transit before arrival at OST";
                else if (new_cksum == client_cksum)
                        msg = "initial checksum before message complete";
                else
                        msg = "changed in transit AND after initial checksum";

                if (req->rq_peer.nid == desc->bd_sender) {
                        via = router = "";
                } else {
                        via = " via ";
                        router = libcfs_nid2str(desc->bd_sender);
                }

                LCONSOLE_ERROR_MSG(0x168, "%s: BAD WRITE CHECKSUM: %s from "
                                   "%s%s%s inode "DFID" object "
                                   LPU64"/"LPU64" extent ["LPU64"-"LPU64"]\n",
                                   exp->exp_obd->obd_name, msg,
                                   libcfs_id2str(req->rq_peer),
                                   via, router,
                                   body->oa.o_valid & OBD_MD_FLFID ?
                                                body->oa.o_parent_seq : (__u64)0,
                                   body->oa.o_valid & OBD_MD_FLFID ?
                                                body->oa.o_parent_oid : 0,
                                   body->oa.o_valid & OBD_MD_FLFID ?
                                                body->oa.o_parent_ver : 0,
                                   body->oa.o_id,
                                   body->oa.o_valid & OBD_MD_FLGROUP ?
                                                body->oa.o_seq : (__u64)0,
                                   local_nb[0].offset,
                                   local_nb[npages-1].offset +
                                   local_nb[npages-1].len - 1 );
                CERROR("client csum %x, original server csum %x, "
                       "server csum now %x\n",
                       client_cksum, server_cksum, new_cksum);
        }

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
                ptlrpc_free_bulk(desc);
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
                CWARN("%s: ignoring bulk IO comm error with %s@%s id %s - "
                      "client will retry\n",
                      exp->exp_obd->obd_name,
                      exp->exp_client_uuid.uuid,
                      exp->exp_connection->c_remote_uuid.uuid,
                      libcfs_id2str(req->rq_peer));
        }
        cfs_memory_pressure_clr();
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
        rc = obd_set_info_async(exp, keylen, key, vallen, val, NULL);
out:
        lustre_msg_set_status(req->rq_repmsg, 0);
        RETURN(rc);
}

static int ost_get_info(struct obd_export *exp, struct ptlrpc_request *req)
{
        void *key, *reply;
        int keylen, replylen, rc = 0;
        struct req_capsule *pill = &req->rq_pill;
        ENTRY;

        /* this common part for get_info rpc */
        key = req_capsule_client_get(pill, &RMF_SETINFO_KEY);
        if (key == NULL) {
                DEBUG_REQ(D_HA, req, "no get_info key");
                RETURN(-EFAULT);
        }
        keylen = req_capsule_get_size(pill, &RMF_SETINFO_KEY, RCL_CLIENT);

        if (KEY_IS(KEY_FIEMAP)) {
                struct ll_fiemap_info_key *fm_key = key;
                int rc;

                rc = ost_validate_obdo(exp, &fm_key->oa, NULL);
                if (rc)
                        RETURN(rc);
        }

        rc = obd_get_info(exp, keylen, key, &replylen, NULL, NULL);
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

        /* call again to fill in the reply buffer */
        rc = obd_get_info(exp, keylen, key, &replylen, reply, NULL);

        lustre_msg_set_status(req->rq_repmsg, 0);
        RETURN(rc);
}

#ifdef HAVE_QUOTA_SUPPORT
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

        req->rq_status = obd_quotacheck(req->rq_export, oqctl);
        RETURN(0);
}

static int ost_handle_quota_adjust_qunit(struct ptlrpc_request *req)
{
        struct quota_adjust_qunit *oqaq, *repoqa;
        struct lustre_quota_ctxt *qctxt;
        int rc;
        ENTRY;

        qctxt = &req->rq_export->exp_obd->u.obt.obt_qctxt;
        oqaq = req_capsule_client_get(&req->rq_pill, &RMF_QUOTA_ADJUST_QUNIT);
        if (oqaq == NULL)
                GOTO(out, rc = -EPROTO);

        rc = req_capsule_server_pack(&req->rq_pill);
        if (rc)
                GOTO(out, rc);

        repoqa = req_capsule_server_get(&req->rq_pill, &RMF_QUOTA_ADJUST_QUNIT);
        req->rq_status = obd_quota_adjust_qunit(req->rq_export, oqaq, qctxt, NULL);
        *repoqa = *oqaq;

 out:
        RETURN(rc);
}
#endif

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

#define ost_init_sec_none(reply, exp)                                   \
do {                                                                    \
        reply->ocd_connect_flags &= ~(OBD_CONNECT_RMT_CLIENT |          \
                                      OBD_CONNECT_RMT_CLIENT_FORCE |    \
                                      OBD_CONNECT_OSS_CAPA);            \
        cfs_spin_lock(&exp->exp_lock);                                  \
        exp->exp_connect_flags = reply->ocd_connect_flags;              \
        cfs_spin_unlock(&exp->exp_lock);                                \
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
                ost_init_sec_none(reply, exp);
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
                        ost_init_sec_none(reply, exp);
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
                        ost_init_sec_none(reply, exp);
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
                        ost_init_sec_none(reply, exp);
                        break;
                } else {
                        CDEBUG(D_SEC, "client %s -> target %s is set as remote, "
                               "can not run under security level %d.\n",
                               client, obd->obd_name, filter->fo_sec_level);
                        RETURN(-EACCES);
                }
        case LUSTRE_SEC_REMOTE:
                if (!remote)
                        ost_init_sec_none(reply, exp);
                break;
        case LUSTRE_SEC_ALL:
                if (!remote) {
                        reply->ocd_connect_flags &= ~(OBD_CONNECT_RMT_CLIENT |
                                                      OBD_CONNECT_RMT_CLIENT_FORCE);
                        if (!filter->fo_fl_oss_capa)
                                reply->ocd_connect_flags &= ~OBD_CONNECT_OSS_CAPA;

                        cfs_spin_lock(&exp->exp_lock);
                        exp->exp_connect_flags = reply->ocd_connect_flags;
                        cfs_spin_unlock(&exp->exp_lock);
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
                cfs_read_lock(&filter->fo_sptlrpc_lock);
                sptlrpc_target_choose_flavor(&filter->fo_sptlrpc_rset,
                                             req->rq_sp_from,
                                             req->rq_peer.nid,
                                             &flvr);
                cfs_read_unlock(&filter->fo_sptlrpc_lock);

                cfs_spin_lock(&exp->exp_lock);

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

                cfs_spin_unlock(&exp->exp_lock);
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
int ost_blocking_ast(struct ldlm_lock *lock,
                             struct ldlm_lock_desc *desc,
                             void *data, int flag)
{
        __u32 sync_lock_cancel = 0;
        __u32 len = sizeof(sync_lock_cancel);
        int rc = 0;
        ENTRY;

        rc = obd_get_info(lock->l_export, sizeof(KEY_SYNC_LOCK_CANCEL),
                          KEY_SYNC_LOCK_CANCEL, &len, &sync_lock_cancel, NULL);

        if (!rc && flag == LDLM_CB_CANCELING &&
            (lock->l_granted_mode & (LCK_PW|LCK_GROUP)) &&
            (sync_lock_cancel == ALWAYS_SYNC_ON_CANCEL ||
             (sync_lock_cancel == BLOCKING_SYNC_ON_CANCEL &&
              lock->l_flags & LDLM_FL_CBPENDING))) {
                struct obd_info *oinfo;
                struct obdo *oa;
                int rc;

                OBD_ALLOC_PTR(oinfo);
                if (!oinfo)
                        RETURN(-ENOMEM);
                OBDO_ALLOC(oa);
                if (!oa) {
                        OBD_FREE_PTR(oinfo);
                        RETURN(-ENOMEM);
                }
                oa->o_id = lock->l_resource->lr_name.name[0];
                oa->o_seq = lock->l_resource->lr_name.name[1];
                oa->o_valid = OBD_MD_FLID|OBD_MD_FLGROUP;
                oinfo->oi_oa = oa;

                rc = obd_sync(lock->l_export, oinfo,
                              lock->l_policy_data.l_extent.start,
                              lock->l_policy_data.l_extent.end, NULL);
                if (rc)
                        CERROR("Error %d syncing data on lock cancel\n", rc);

                OBDO_FREE(oa);
                OBD_FREE_PTR(oinfo);
        }

        rc = ldlm_server_blocking_ast(lock, desc, data, flag);
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
                DEBUG_REQ(D_ERROR, req, "not permitted during recovery");
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
#ifdef HAVE_QUOTA_SUPPORT
        case OST_QUOTACHECK:
        case OST_QUOTACTL:
        case OST_QUOTA_ADJUST_QUNIT:
#endif
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
        default:
                CERROR("Unexpected opcode %d\n", lustre_msg_get_opc(msg));
                rc = -ENOTSUPP;
        }
        return rc;
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
        struct ost_body *body;
        int objcount, niocount;
        int mode, opc, i, rc;
        __u64 start, end;
        ENTRY;

        opc = lustre_msg_get_opc(req->rq_reqmsg);
        LASSERT(opc == OST_READ || opc == OST_WRITE);

        /* As the request may be covered by several locks, do not look at
         * o_handle, look at the RPC IO region. */
        body = req_capsule_client_get(&req->rq_pill, &RMF_OST_BODY);
        if (body == NULL)
                RETURN(0);

        objcount = req_capsule_get_size(&req->rq_pill, &RMF_OBD_IOOBJ,
                                        RCL_CLIENT) / sizeof(*ioo);
        ioo = req_capsule_client_get(&req->rq_pill, &RMF_OBD_IOOBJ);
        if (ioo == NULL)
                RETURN(0);

        rc = ost_validate_obdo(req->rq_export, &body->oa, ioo);
        if (rc)
                RETURN(rc);

        for (niocount = i = 0; i < objcount; i++)
                niocount += ioo[i].ioo_bufcnt;

        nb = req_capsule_client_get(&req->rq_pill, &RMF_NIOBUF_REMOTE);
        if (nb == NULL ||
            niocount != (req_capsule_get_size(&req->rq_pill, &RMF_NIOBUF_REMOTE,
            RCL_CLIENT) / sizeof(*nb)))
                RETURN(0);

        mode = LCK_PW;
        if (opc == OST_READ)
                mode |= LCK_PR;

        start = nb[0].offset & CFS_PAGE_MASK;
        end = (nb[ioo->ioo_bufcnt - 1].offset +
               nb[ioo->ioo_bufcnt - 1].len - 1) | ~CFS_PAGE_MASK;

        LASSERT(lock->l_resource != NULL);
        if (!osc_res_name_eq(ioo->ioo_id, ioo->ioo_seq,
                             &lock->l_resource->lr_name))
                RETURN(0);

        if (!(lock->l_granted_mode & mode))
                RETURN(0);

        if (lock->l_policy_data.l_extent.end < start ||
            lock->l_policy_data.l_extent.start > end)
                RETURN(0);

        RETURN(1);
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
        struct niobuf_remote *nb;
        struct obd_ioobj *ioo;
        struct ost_body *body;
        int objcount, niocount;
        int mode, opc, i, rc;
        ENTRY;

        opc = lustre_msg_get_opc(req->rq_reqmsg);
        LASSERT(opc == OST_READ || opc == OST_WRITE);

        body = req_capsule_client_get(&req->rq_pill, &RMF_OST_BODY);
        if (body == NULL)
                RETURN(-EFAULT);

        objcount = req_capsule_get_size(&req->rq_pill, &RMF_OBD_IOOBJ,
                                        RCL_CLIENT) / sizeof(*ioo);
        ioo = req_capsule_client_get(&req->rq_pill, &RMF_OBD_IOOBJ);
        if (ioo == NULL)
                RETURN(-EFAULT);

        rc = ost_validate_obdo(req->rq_export, &body->oa, ioo);
        if (rc)
                RETURN(rc);

        for (niocount = i = 0; i < objcount; i++)
                niocount += ioo[i].ioo_bufcnt;
        nb = req_capsule_client_get(&req->rq_pill, &RMF_NIOBUF_REMOTE);
        if (nb == NULL ||
            niocount != (req_capsule_get_size(&req->rq_pill, &RMF_NIOBUF_REMOTE,
            RCL_CLIENT) / sizeof(*nb)))
                RETURN(-EFAULT);
        if (niocount != 0 && (nb[0].flags & OBD_BRW_SRVLOCK))
                RETURN(-EFAULT);

        mode = LCK_PW;
        if (opc == OST_READ)
                mode |= LCK_PR;
        RETURN(ost_rw_prolong_locks(req, ioo, nb, &body->oa, mode));
}

static int ost_punch_prolong_locks(struct ptlrpc_request *req, struct obdo *oa)
{
        struct ldlm_res_id res_id = { .name = { oa->o_id } };
        struct ost_prolong_data opd = { 0 };
        __u64 start, end;
        ENTRY;

        start = oa->o_size;
        end = start + oa->o_blocks;

        opd.opd_mode = LCK_PW;
        opd.opd_exp = req->rq_export;
        opd.opd_policy.l_extent.start = start & CFS_PAGE_MASK;
        if (oa->o_blocks == OBD_OBJECT_EOF || end < start)
                opd.opd_policy.l_extent.end = OBD_OBJECT_EOF;
        else
                opd.opd_policy.l_extent.end = end | ~CFS_PAGE_MASK;

        /* prolong locks for the current service time of the corresponding
         * portal (= OST_IO_PORTAL) */
        opd.opd_timeout = AT_OFF ? obd_timeout / 2:
                          max(at_est2timeout(at_get(&req->rq_rqbd->
                              rqbd_service->srv_at_estimate)), ldlm_timeout);

        CDEBUG(D_DLMTRACE,"refresh locks: "LPU64"/"LPU64" ("LPU64"->"LPU64")\n",
               res_id.name[0], res_id.name[1], opd.opd_policy.l_extent.start,
               opd.opd_policy.l_extent.end);

        opd.opd_oa = oa;
        ldlm_resource_iterate(req->rq_export->exp_obd->obd_namespace, &res_id,
                              ost_prolong_locks_iter, &opd);
        RETURN(opd.opd_lock_match);
}

/**
 * Like ost_rw_hpreq_lock_match(), but for OST_PUNCH RPCs.
 */
static int ost_punch_hpreq_lock_match(struct ptlrpc_request *req,
                                      struct ldlm_lock *lock)
{
        struct ost_body *body;
        int rc;
        ENTRY;

        body = req_capsule_client_get(&req->rq_pill, &RMF_OST_BODY);
        if (body == NULL)
                RETURN(0);  /* can't return -EFAULT here */

        rc = ost_validate_obdo(req->rq_export, &body->oa, NULL);
        if (rc)
                RETURN(rc);

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
        struct ost_body *body;
        int rc;

        body = req_capsule_client_get(&req->rq_pill, &RMF_OST_BODY);
        if (body == NULL)
                RETURN(-EFAULT);

        rc = ost_validate_obdo(req->rq_export, &body->oa, NULL);
        if (rc)
                RETURN(rc);

        LASSERT(!(body->oa.o_valid & OBD_MD_FLFLAGS) ||
                !(body->oa.o_flags & OBD_FL_SRVLOCK));

        RETURN(ost_punch_prolong_locks(req, &body->oa));
}

struct ptlrpc_hpreq_ops ost_hpreq_rw = {
        .hpreq_lock_match  = ost_rw_hpreq_lock_match,
        .hpreq_check       = ost_rw_hpreq_check,
};

struct ptlrpc_hpreq_ops ost_hpreq_punch = {
        .hpreq_lock_match  = ost_punch_hpreq_lock_match,
        .hpreq_check       = ost_punch_hpreq_check,
};

/** Assign high priority operations to the request if needed. */
static int ost_hpreq_handler(struct ptlrpc_request *req)
{
        ENTRY;
        if (req->rq_export) {
                int opc = lustre_msg_get_opc(req->rq_reqmsg);
                struct ost_body *body;

                if (opc == OST_READ || opc == OST_WRITE) {
                        struct niobuf_remote *nb;
                        struct obd_ioobj *ioo;
                        int objcount, niocount;
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
        ENTRY;

        LASSERT(current->journal_info == NULL);

        /* primordial rpcs don't affect server recovery */
        switch (lustre_msg_get_opc(req->rq_reqmsg)) {
        case SEC_CTX_INIT:
        case SEC_CTX_INIT_CONT:
        case SEC_CTX_FINI:
                GOTO(out, rc = 0);
        }

        req_capsule_init(&req->rq_pill, req, RCL_SERVER);

        if (lustre_msg_get_opc(req->rq_reqmsg) != OST_CONNECT) {
                if (!class_connected_export(req->rq_export)) {
                        CDEBUG(D_HA,"operation %d on unconnected OST from %s\n",
                               lustre_msg_get_opc(req->rq_reqmsg),
                               libcfs_id2str(req->rq_peer));
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

        switch (lustre_msg_get_opc(req->rq_reqmsg)) {
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
                if (req->rq_rqbd->rqbd_service->srv_req_portal !=OST_IO_PORTAL){
                        CERROR("%s: deny write request from %s to portal %u\n",
                               req->rq_export->exp_obd->obd_name,
                               obd_export_nid2str(req->rq_export),
                               req->rq_rqbd->rqbd_service->srv_req_portal);
                        GOTO(out, rc = -EPROTO);
                }
                if (OBD_FAIL_CHECK(OBD_FAIL_OST_BRW_NET))
                        RETURN(0);
                if (OBD_FAIL_CHECK(OBD_FAIL_OST_ENOSPC))
                        GOTO(out, rc = -ENOSPC);
                if (OBD_FAIL_CHECK(OBD_FAIL_OST_EROFS))
                        GOTO(out, rc = -EROFS);
                rc = ost_brw_write(req, oti);
                LASSERT(current->journal_info == NULL);
                /* ost_brw_write sends its own replies */
                RETURN(rc);
        case OST_READ:
                req_capsule_set(&req->rq_pill, &RQF_OST_BRW_READ);
                CDEBUG(D_INODE, "read\n");
                /* req->rq_request_portal would be nice, if it was set */
                if (req->rq_rqbd->rqbd_service->srv_req_portal !=OST_IO_PORTAL){
                        CERROR("%s: deny read request from %s to portal %u\n",
                               req->rq_export->exp_obd->obd_name,
                               obd_export_nid2str(req->rq_export),
                               req->rq_rqbd->rqbd_service->srv_req_portal);
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
                rc = ost_sync(req->rq_export, req);
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
#ifdef HAVE_QUOTA_SUPPORT
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
        case OST_QUOTA_ADJUST_QUNIT:
                CDEBUG(D_INODE, "quota_adjust_qunit\n");
                req_capsule_set(&req->rq_pill, &RQF_OST_QUOTA_ADJUST_QUNIT);
                rc = ost_handle_quota_adjust_qunit(req);
                break;
#endif
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
        case OBD_LOG_CANCEL:
                CDEBUG(D_INODE, "log cancel\n");
                req_capsule_set(&req->rq_pill, &RQF_LOG_CANCEL);
                if (OBD_FAIL_CHECK(OBD_FAIL_OBD_LOG_CANCEL_NET))
                        RETURN(0);
                rc = llog_origin_handle_cancel(req);
                if (OBD_FAIL_CHECK(OBD_FAIL_OBD_LOG_CANCEL_REP))
                        RETURN(0);
                req->rq_status = rc;
                rc = req_capsule_server_pack(&req->rq_pill);
                if (rc)
                        RETURN(rc);
                RETURN(ptlrpc_reply(req));
        case LDLM_ENQUEUE:
                CDEBUG(D_INODE, "enqueue\n");
                req_capsule_set(&req->rq_pill, &RQF_LDLM_ENQUEUE);
                if (OBD_FAIL_CHECK(OBD_FAIL_LDLM_ENQUEUE))
                        RETURN(0);
                rc = ldlm_handle_enqueue(req, ldlm_server_completion_ast,
                                         ost_blocking_ast,
                                         ldlm_server_glimpse_ast);
                fail = OBD_FAIL_OST_LDLM_REPLY_NET;
                break;
        case LDLM_CONVERT:
                CDEBUG(D_INODE, "convert\n");
                req_capsule_set(&req->rq_pill, &RQF_LDLM_CONVERT);
                if (OBD_FAIL_CHECK(OBD_FAIL_LDLM_CONVERT))
                        RETURN(0);
                rc = ldlm_handle_convert(req);
                break;
        case LDLM_CANCEL:
                CDEBUG(D_INODE, "cancel\n");
                req_capsule_set(&req->rq_pill, &RQF_LDLM_CANCEL);
                if (OBD_FAIL_CHECK(OBD_FAIL_LDLM_CANCEL))
                        RETURN(0);
                rc = ldlm_handle_cancel(req);
                break;
        case LDLM_BL_CALLBACK:
        case LDLM_CP_CALLBACK:
                CDEBUG(D_INODE, "callback\n");
                CERROR("callbacks should not happen on OST\n");
                /* fall through */
        default:
                CERROR("Unexpected opcode %d\n",
                       lustre_msg_get_opc(req->rq_reqmsg));
                req->rq_status = -ENOTSUPP;
                rc = ptlrpc_error(req);
                RETURN(rc);
        }

        LASSERT(current->journal_info == NULL);

        EXIT;
        /* If we're DISCONNECTing, the export_data is already freed */
        if (!rc && lustre_msg_get_opc(req->rq_reqmsg) != OST_DISCONNECT)
                target_committed_to_req(req);

out:
        if (!rc)
                oti_to_request(oti, req);

        target_send_reply(req, rc, fail);
        return 0;
}
EXPORT_SYMBOL(ost_handle);
/*
 * free per-thread pool created by ost_thread_init().
 */
static void ost_thread_done(struct ptlrpc_thread *thread)
{
        struct ost_thread_local_cache *tls; /* TLS stands for Thread-Local
                                             * Storage */

        ENTRY;

        LASSERT(thread != NULL);

        /*
         * be prepared to handle partially-initialized pools (because this is
         * called from ost_thread_init() for cleanup.
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
static int ost_thread_init(struct ptlrpc_thread *thread)
{
        struct ost_thread_local_cache *tls;

        ENTRY;

        LASSERT(thread != NULL);
        LASSERT(thread->t_data == NULL);
        LASSERTF(thread->t_id <= OSS_THREADS_MAX, "%u\n", thread->t_id);

        OBD_ALLOC_PTR(tls);
        if (tls == NULL)
                RETURN(-ENOMEM);
        thread->t_data = tls;
        RETURN(0);
}

#define OST_WATCHDOG_TIMEOUT (obd_timeout * 1000)

/* Sigh - really, this is an OSS, the _server_, not the _target_ */
static int ost_setup(struct obd_device *obd, struct lustre_cfg* lcfg)
{
        struct ost_obd *ost = &obd->u.ost;
        struct lprocfs_static_vars lvars;
        int oss_min_threads;
        int oss_max_threads;
        int oss_min_create_threads;
        int oss_max_create_threads;
        int rc;
        ENTRY;

        rc = cfs_cleanup_group_info();
        if (rc)
                RETURN(rc);

        lprocfs_ost_init_vars(&lvars);
        lprocfs_obd_setup(obd, lvars.obd_vars);

        cfs_sema_init(&ost->ost_health_sem, 1);

        if (oss_num_threads) {
                /* If oss_num_threads is set, it is the min and the max. */
                if (oss_num_threads > OSS_THREADS_MAX)
                        oss_num_threads = OSS_THREADS_MAX;
                if (oss_num_threads < OSS_THREADS_MIN)
                        oss_num_threads = OSS_THREADS_MIN;
                oss_max_threads = oss_min_threads = oss_num_threads;
        } else {
                /* Base min threads on memory and cpus */
                oss_min_threads =
                        cfs_num_possible_cpus() * CFS_NUM_CACHEPAGES >>
                        (27 - CFS_PAGE_SHIFT);
                if (oss_min_threads < OSS_THREADS_MIN)
                        oss_min_threads = OSS_THREADS_MIN;
                /* Insure a 4x range for dynamic threads */
                if (oss_min_threads > OSS_THREADS_MAX / 4)
                        oss_min_threads = OSS_THREADS_MAX / 4;
                oss_max_threads = min(OSS_THREADS_MAX, oss_min_threads * 4 + 1);
        }

        ost->ost_service =
                ptlrpc_init_svc(OST_NBUFS, OST_BUFSIZE, OST_MAXREQSIZE,
                                OST_MAXREPSIZE, OST_REQUEST_PORTAL,
                                OSC_REPLY_PORTAL, OSS_SERVICE_WATCHDOG_FACTOR,
                                ost_handle, LUSTRE_OSS_NAME,
                                obd->obd_proc_entry, target_print_req,
                                oss_min_threads, oss_max_threads,
                                "ll_ost", LCT_DT_THREAD, NULL);
        if (ost->ost_service == NULL) {
                CERROR("failed to start service\n");
                GOTO(out_lprocfs, rc = -ENOMEM);
        }

        rc = ptlrpc_start_threads(ost->ost_service);
        if (rc)
                GOTO(out_service, rc = -EINVAL);

        if (oss_num_create_threads) {
                if (oss_num_create_threads > OSS_MAX_CREATE_THREADS)
                        oss_num_create_threads = OSS_MAX_CREATE_THREADS;
                if (oss_num_create_threads < OSS_MIN_CREATE_THREADS)
                        oss_num_create_threads = OSS_MIN_CREATE_THREADS;
                oss_min_create_threads = oss_max_create_threads =
                        oss_num_create_threads;
        } else {
                oss_min_create_threads = OSS_MIN_CREATE_THREADS;
                oss_max_create_threads = OSS_MAX_CREATE_THREADS;
        }

        ost->ost_create_service =
                ptlrpc_init_svc(OST_NBUFS, OST_BUFSIZE, OST_MAXREQSIZE,
                                OST_MAXREPSIZE, OST_CREATE_PORTAL,
                                OSC_REPLY_PORTAL, OSS_SERVICE_WATCHDOG_FACTOR,
                                ost_handle, "ost_create",
                                obd->obd_proc_entry, target_print_req,
                                oss_min_create_threads, oss_max_create_threads,
                                "ll_ost_creat", LCT_DT_THREAD, NULL);
        if (ost->ost_create_service == NULL) {
                CERROR("failed to start OST create service\n");
                GOTO(out_service, rc = -ENOMEM);
        }

        rc = ptlrpc_start_threads(ost->ost_create_service);
        if (rc)
                GOTO(out_create, rc = -EINVAL);

        ost->ost_io_service =
                ptlrpc_init_svc(OST_NBUFS, OST_BUFSIZE, OST_MAXREQSIZE,
                                OST_MAXREPSIZE, OST_IO_PORTAL,
                                OSC_REPLY_PORTAL, OSS_SERVICE_WATCHDOG_FACTOR,
                                ost_handle, "ost_io",
                                obd->obd_proc_entry, target_print_req,
                                oss_min_threads, oss_max_threads,
                                "ll_ost_io", LCT_DT_THREAD, ost_hpreq_handler);
        if (ost->ost_io_service == NULL) {
                CERROR("failed to start OST I/O service\n");
                GOTO(out_create, rc = -ENOMEM);
        }

        ost->ost_io_service->srv_init = ost_thread_init;
        ost->ost_io_service->srv_done = ost_thread_done;
        ost->ost_io_service->srv_cpu_affinity = 1;
        rc = ptlrpc_start_threads(ost->ost_io_service);
        if (rc)
                GOTO(out_io, rc = -EINVAL);

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
        cfs_down(&ost->ost_health_sem);
        ptlrpc_unregister_service(ost->ost_service);
        ptlrpc_unregister_service(ost->ost_create_service);
        ptlrpc_unregister_service(ost->ost_io_service);
        ost->ost_service = NULL;
        ost->ost_create_service = NULL;
        cfs_up(&ost->ost_health_sem);

        lprocfs_obd_cleanup(obd);

        RETURN(err);
}

static int ost_health_check(struct obd_device *obd)
{
        struct ost_obd *ost = &obd->u.ost;
        int rc = 0;

        cfs_down(&ost->ost_health_sem);
        rc |= ptlrpc_service_health_check(ost->ost_service);
        rc |= ptlrpc_service_health_check(ost->ost_create_service);
        rc |= ptlrpc_service_health_check(ost->ost_io_service);
        cfs_up(&ost->ost_health_sem);

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
