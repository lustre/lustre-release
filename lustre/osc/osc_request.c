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
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright (c) 2011 Whamcloud, Inc.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_OSC

#include <libcfs/libcfs.h>

#ifndef __KERNEL__
# include <liblustre.h>
#endif

#include <lustre_dlm.h>
#include <lustre_net.h>
#include <lustre/lustre_user.h>
#include <obd_cksum.h>
#include <obd_ost.h>
#include <obd_lov.h>

#ifdef  __CYGWIN__
# include <ctype.h>
#endif

#include <lustre_ha.h>
#include <lprocfs_status.h>
#include <lustre_log.h>
#include <lustre_debug.h>
#include <lustre_param.h>
#include "osc_internal.h"

static quota_interface_t *quota_interface = NULL;
extern quota_interface_t osc_quota_interface;

static void osc_release_ppga(struct brw_page **ppga, obd_count count);
static int brw_interpret(const struct lu_env *env,
                         struct ptlrpc_request *req, void *data, int rc);
int osc_cleanup(struct obd_device *obd);

/* Pack OSC object metadata for disk storage (LE byte order). */
static int osc_packmd(struct obd_export *exp, struct lov_mds_md **lmmp,
                      struct lov_stripe_md *lsm)
{
        int lmm_size;
        ENTRY;

        lmm_size = sizeof(**lmmp);
        if (!lmmp)
                RETURN(lmm_size);

        if (*lmmp && !lsm) {
                OBD_FREE(*lmmp, lmm_size);
                *lmmp = NULL;
                RETURN(0);
        }

        if (!*lmmp) {
                OBD_ALLOC(*lmmp, lmm_size);
                if (!*lmmp)
                        RETURN(-ENOMEM);
        }

        if (lsm) {
                LASSERT(lsm->lsm_object_id);
                LASSERT_SEQ_IS_MDT(lsm->lsm_object_seq);
                (*lmmp)->lmm_object_id = cpu_to_le64(lsm->lsm_object_id);
                (*lmmp)->lmm_object_seq = cpu_to_le64(lsm->lsm_object_seq);
        }

        RETURN(lmm_size);
}

/* Unpack OSC object metadata from disk storage (LE byte order). */
static int osc_unpackmd(struct obd_export *exp, struct lov_stripe_md **lsmp,
                        struct lov_mds_md *lmm, int lmm_bytes)
{
        int lsm_size;
        struct obd_import *imp = class_exp2cliimp(exp);
        ENTRY;

        if (lmm != NULL) {
                if (lmm_bytes < sizeof (*lmm)) {
                        CERROR("lov_mds_md too small: %d, need %d\n",
                               lmm_bytes, (int)sizeof(*lmm));
                        RETURN(-EINVAL);
                }
                /* XXX LOV_MAGIC etc check? */

                if (lmm->lmm_object_id == 0) {
                        CERROR("lov_mds_md: zero lmm_object_id\n");
                        RETURN(-EINVAL);
                }
        }

        lsm_size = lov_stripe_md_size(1);
        if (lsmp == NULL)
                RETURN(lsm_size);

        if (*lsmp != NULL && lmm == NULL) {
                OBD_FREE((*lsmp)->lsm_oinfo[0], sizeof(struct lov_oinfo));
                OBD_FREE(*lsmp, lsm_size);
                *lsmp = NULL;
                RETURN(0);
        }

        if (*lsmp == NULL) {
                OBD_ALLOC(*lsmp, lsm_size);
                if (*lsmp == NULL)
                        RETURN(-ENOMEM);
                OBD_ALLOC((*lsmp)->lsm_oinfo[0], sizeof(struct lov_oinfo));
                if ((*lsmp)->lsm_oinfo[0] == NULL) {
                        OBD_FREE(*lsmp, lsm_size);
                        RETURN(-ENOMEM);
                }
                loi_init((*lsmp)->lsm_oinfo[0]);
        }

        if (lmm != NULL) {
                /* XXX zero *lsmp? */
                (*lsmp)->lsm_object_id = le64_to_cpu (lmm->lmm_object_id);
                (*lsmp)->lsm_object_seq = le64_to_cpu (lmm->lmm_object_seq);
                LASSERT((*lsmp)->lsm_object_id);
                LASSERT_SEQ_IS_MDT((*lsmp)->lsm_object_seq);
        }

        if (imp != NULL &&
            (imp->imp_connect_data.ocd_connect_flags & OBD_CONNECT_MAXBYTES))
                (*lsmp)->lsm_maxbytes = imp->imp_connect_data.ocd_maxbytes;
        else
                (*lsmp)->lsm_maxbytes = LUSTRE_STRIPE_MAXBYTES;

        RETURN(lsm_size);
}

static inline void osc_pack_capa(struct ptlrpc_request *req,
                                 struct ost_body *body, void *capa)
{
        struct obd_capa *oc = (struct obd_capa *)capa;
        struct lustre_capa *c;

        if (!capa)
                return;

        c = req_capsule_client_get(&req->rq_pill, &RMF_CAPA1);
        LASSERT(c);
        capa_cpy(c, oc);
        body->oa.o_valid |= OBD_MD_FLOSSCAPA;
        DEBUG_CAPA(D_SEC, c, "pack");
}

static inline void osc_pack_req_body(struct ptlrpc_request *req,
                                     struct obd_info *oinfo)
{
        struct ost_body *body;

        body = req_capsule_client_get(&req->rq_pill, &RMF_OST_BODY);
        LASSERT(body);

        lustre_set_wire_obdo(&body->oa, oinfo->oi_oa);
        osc_pack_capa(req, body, oinfo->oi_capa);
}

static inline void osc_set_capa_size(struct ptlrpc_request *req,
                                     const struct req_msg_field *field,
                                     struct obd_capa *oc)
{
        if (oc == NULL)
                req_capsule_set_size(&req->rq_pill, field, RCL_CLIENT, 0);
        else
                /* it is already calculated as sizeof struct obd_capa */
                ;
}

static int osc_getattr_interpret(const struct lu_env *env,
                                 struct ptlrpc_request *req,
                                 struct osc_async_args *aa, int rc)
{
        struct ost_body *body;
        ENTRY;

        if (rc != 0)
                GOTO(out, rc);

        body = req_capsule_server_get(&req->rq_pill, &RMF_OST_BODY);
        if (body) {
                CDEBUG(D_INODE, "mode: %o\n", body->oa.o_mode);
                lustre_get_wire_obdo(aa->aa_oi->oi_oa, &body->oa);

                /* This should really be sent by the OST */
                aa->aa_oi->oi_oa->o_blksize = PTLRPC_MAX_BRW_SIZE;
                aa->aa_oi->oi_oa->o_valid |= OBD_MD_FLBLKSZ;
        } else {
                CDEBUG(D_INFO, "can't unpack ost_body\n");
                rc = -EPROTO;
                aa->aa_oi->oi_oa->o_valid = 0;
        }
out:
        rc = aa->aa_oi->oi_cb_up(aa->aa_oi, rc);
        RETURN(rc);
}

static int osc_getattr_async(struct obd_export *exp, struct obd_info *oinfo,
                             struct ptlrpc_request_set *set)
{
        struct ptlrpc_request *req;
        struct osc_async_args *aa;
        int                    rc;
        ENTRY;

        req = ptlrpc_request_alloc(class_exp2cliimp(exp), &RQF_OST_GETATTR);
        if (req == NULL)
                RETURN(-ENOMEM);

        osc_set_capa_size(req, &RMF_CAPA1, oinfo->oi_capa);
        rc = ptlrpc_request_pack(req, LUSTRE_OST_VERSION, OST_GETATTR);
        if (rc) {
                ptlrpc_request_free(req);
                RETURN(rc);
        }

        osc_pack_req_body(req, oinfo);

        ptlrpc_request_set_replen(req);
        req->rq_interpret_reply = (ptlrpc_interpterer_t)osc_getattr_interpret;

        CLASSERT(sizeof(*aa) <= sizeof(req->rq_async_args));
        aa = ptlrpc_req_async_args(req);
        aa->aa_oi = oinfo;

        ptlrpc_set_add_req(set, req);
        RETURN(0);
}

static int osc_getattr(struct obd_export *exp, struct obd_info *oinfo)
{
        struct ptlrpc_request *req;
        struct ost_body       *body;
        int                    rc;
        ENTRY;

        req = ptlrpc_request_alloc(class_exp2cliimp(exp), &RQF_OST_GETATTR);
        if (req == NULL)
                RETURN(-ENOMEM);

        osc_set_capa_size(req, &RMF_CAPA1, oinfo->oi_capa);
        rc = ptlrpc_request_pack(req, LUSTRE_OST_VERSION, OST_GETATTR);
        if (rc) {
                ptlrpc_request_free(req);
                RETURN(rc);
        }

        osc_pack_req_body(req, oinfo);

        ptlrpc_request_set_replen(req);

        rc = ptlrpc_queue_wait(req);
        if (rc)
                GOTO(out, rc);

        body = req_capsule_server_get(&req->rq_pill, &RMF_OST_BODY);
        if (body == NULL)
                GOTO(out, rc = -EPROTO);

        CDEBUG(D_INODE, "mode: %o\n", body->oa.o_mode);
        lustre_get_wire_obdo(oinfo->oi_oa, &body->oa);

        /* This should really be sent by the OST */
        oinfo->oi_oa->o_blksize = PTLRPC_MAX_BRW_SIZE;
        oinfo->oi_oa->o_valid |= OBD_MD_FLBLKSZ;

        EXIT;
 out:
        ptlrpc_req_finished(req);
        return rc;
}

static int osc_setattr(struct obd_export *exp, struct obd_info *oinfo,
                       struct obd_trans_info *oti)
{
        struct ptlrpc_request *req;
        struct ost_body       *body;
        int                    rc;
        ENTRY;

        LASSERT(oinfo->oi_oa->o_valid & OBD_MD_FLGROUP);

        req = ptlrpc_request_alloc(class_exp2cliimp(exp), &RQF_OST_SETATTR);
        if (req == NULL)
                RETURN(-ENOMEM);

        osc_set_capa_size(req, &RMF_CAPA1, oinfo->oi_capa);
        rc = ptlrpc_request_pack(req, LUSTRE_OST_VERSION, OST_SETATTR);
        if (rc) {
                ptlrpc_request_free(req);
                RETURN(rc);
        }

        osc_pack_req_body(req, oinfo);

        ptlrpc_request_set_replen(req);

        rc = ptlrpc_queue_wait(req);
        if (rc)
                GOTO(out, rc);

        body = req_capsule_server_get(&req->rq_pill, &RMF_OST_BODY);
        if (body == NULL)
                GOTO(out, rc = -EPROTO);

        lustre_get_wire_obdo(oinfo->oi_oa, &body->oa);

        EXIT;
out:
        ptlrpc_req_finished(req);
        RETURN(rc);
}

static int osc_setattr_interpret(const struct lu_env *env,
                                 struct ptlrpc_request *req,
                                 struct osc_setattr_args *sa, int rc)
{
        struct ost_body *body;
        ENTRY;

        if (rc != 0)
                GOTO(out, rc);

        body = req_capsule_server_get(&req->rq_pill, &RMF_OST_BODY);
        if (body == NULL)
                GOTO(out, rc = -EPROTO);

        lustre_get_wire_obdo(sa->sa_oa, &body->oa);
out:
        rc = sa->sa_upcall(sa->sa_cookie, rc);
        RETURN(rc);
}

int osc_setattr_async_base(struct obd_export *exp, struct obd_info *oinfo,
                           struct obd_trans_info *oti,
                           obd_enqueue_update_f upcall, void *cookie,
                           struct ptlrpc_request_set *rqset)
{
        struct ptlrpc_request   *req;
        struct osc_setattr_args *sa;
        int                      rc;
        ENTRY;

        req = ptlrpc_request_alloc(class_exp2cliimp(exp), &RQF_OST_SETATTR);
        if (req == NULL)
                RETURN(-ENOMEM);

        osc_set_capa_size(req, &RMF_CAPA1, oinfo->oi_capa);
        rc = ptlrpc_request_pack(req, LUSTRE_OST_VERSION, OST_SETATTR);
        if (rc) {
                ptlrpc_request_free(req);
                RETURN(rc);
        }

        if (oti && oinfo->oi_oa->o_valid & OBD_MD_FLCOOKIE)
                oinfo->oi_oa->o_lcookie = *oti->oti_logcookies;

        osc_pack_req_body(req, oinfo);

        ptlrpc_request_set_replen(req);

        /* do mds to ost setattr asynchronously */
        if (!rqset) {
                /* Do not wait for response. */
                ptlrpcd_add_req(req, PSCOPE_OTHER);
        } else {
                req->rq_interpret_reply =
                        (ptlrpc_interpterer_t)osc_setattr_interpret;

                CLASSERT (sizeof(*sa) <= sizeof(req->rq_async_args));
                sa = ptlrpc_req_async_args(req);
                sa->sa_oa = oinfo->oi_oa;
                sa->sa_upcall = upcall;
                sa->sa_cookie = cookie;

                if (rqset == PTLRPCD_SET)
                        ptlrpcd_add_req(req, PSCOPE_OTHER);
                else
                        ptlrpc_set_add_req(rqset, req);
        }

        RETURN(0);
}

static int osc_setattr_async(struct obd_export *exp, struct obd_info *oinfo,
                             struct obd_trans_info *oti,
                             struct ptlrpc_request_set *rqset)
{
        return osc_setattr_async_base(exp, oinfo, oti,
                                      oinfo->oi_cb_up, oinfo, rqset);
}

int osc_real_create(struct obd_export *exp, struct obdo *oa,
                    struct lov_stripe_md **ea, struct obd_trans_info *oti)
{
        struct ptlrpc_request *req;
        struct ost_body       *body;
        struct lov_stripe_md  *lsm;
        int                    rc;
        ENTRY;

        LASSERT(oa);
        LASSERT(ea);

        lsm = *ea;
        if (!lsm) {
                rc = obd_alloc_memmd(exp, &lsm);
                if (rc < 0)
                        RETURN(rc);
        }

        req = ptlrpc_request_alloc(class_exp2cliimp(exp), &RQF_OST_CREATE);
        if (req == NULL)
                GOTO(out, rc = -ENOMEM);

        rc = ptlrpc_request_pack(req, LUSTRE_OST_VERSION, OST_CREATE);
        if (rc) {
                ptlrpc_request_free(req);
                GOTO(out, rc);
        }

        body = req_capsule_client_get(&req->rq_pill, &RMF_OST_BODY);
        LASSERT(body);
        lustre_set_wire_obdo(&body->oa, oa);

        ptlrpc_request_set_replen(req);

        if ((oa->o_valid & OBD_MD_FLFLAGS) &&
            oa->o_flags == OBD_FL_DELORPHAN) {
                DEBUG_REQ(D_HA, req,
                          "delorphan from OST integration");
                /* Don't resend the delorphan req */
                req->rq_no_resend = req->rq_no_delay = 1;
        }

        rc = ptlrpc_queue_wait(req);
        if (rc)
                GOTO(out_req, rc);

        body = req_capsule_server_get(&req->rq_pill, &RMF_OST_BODY);
        if (body == NULL)
                GOTO(out_req, rc = -EPROTO);

        lustre_get_wire_obdo(oa, &body->oa);

        /* This should really be sent by the OST */
        oa->o_blksize = PTLRPC_MAX_BRW_SIZE;
        oa->o_valid |= OBD_MD_FLBLKSZ;

        /* XXX LOV STACKING: the lsm that is passed to us from LOV does not
         * have valid lsm_oinfo data structs, so don't go touching that.
         * This needs to be fixed in a big way.
         */
        lsm->lsm_object_id = oa->o_id;
        lsm->lsm_object_seq = oa->o_seq;
        *ea = lsm;

        if (oti != NULL) {
                oti->oti_transno = lustre_msg_get_transno(req->rq_repmsg);

                if (oa->o_valid & OBD_MD_FLCOOKIE) {
                        if (!oti->oti_logcookies)
                                oti_alloc_cookies(oti, 1);
                        *oti->oti_logcookies = oa->o_lcookie;
                }
        }

        CDEBUG(D_HA, "transno: "LPD64"\n",
               lustre_msg_get_transno(req->rq_repmsg));
out_req:
        ptlrpc_req_finished(req);
out:
        if (rc && !*ea)
                obd_free_memmd(exp, &lsm);
        RETURN(rc);
}

int osc_punch_base(struct obd_export *exp, struct obd_info *oinfo,
                   obd_enqueue_update_f upcall, void *cookie,
                   struct ptlrpc_request_set *rqset)
{
        struct ptlrpc_request   *req;
        struct osc_setattr_args *sa;
        struct ost_body         *body;
        int                      rc;
        ENTRY;

        req = ptlrpc_request_alloc(class_exp2cliimp(exp), &RQF_OST_PUNCH);
        if (req == NULL)
                RETURN(-ENOMEM);

        osc_set_capa_size(req, &RMF_CAPA1, oinfo->oi_capa);
        rc = ptlrpc_request_pack(req, LUSTRE_OST_VERSION, OST_PUNCH);
        if (rc) {
                ptlrpc_request_free(req);
                RETURN(rc);
        }
        req->rq_request_portal = OST_IO_PORTAL; /* bug 7198 */
        ptlrpc_at_set_req_timeout(req);

        body = req_capsule_client_get(&req->rq_pill, &RMF_OST_BODY);
        LASSERT(body);
        lustre_set_wire_obdo(&body->oa, oinfo->oi_oa);
        osc_pack_capa(req, body, oinfo->oi_capa);

        ptlrpc_request_set_replen(req);


        req->rq_interpret_reply = (ptlrpc_interpterer_t)osc_setattr_interpret;
        CLASSERT (sizeof(*sa) <= sizeof(req->rq_async_args));
        sa = ptlrpc_req_async_args(req);
        sa->sa_oa     = oinfo->oi_oa;
        sa->sa_upcall = upcall;
        sa->sa_cookie = cookie;
        if (rqset == PTLRPCD_SET)
                ptlrpcd_add_req(req, PSCOPE_OTHER);
        else
                ptlrpc_set_add_req(rqset, req);

        RETURN(0);
}

static int osc_punch(struct obd_export *exp, struct obd_info *oinfo,
                     struct obd_trans_info *oti,
                     struct ptlrpc_request_set *rqset)
{
        oinfo->oi_oa->o_size   = oinfo->oi_policy.l_extent.start;
        oinfo->oi_oa->o_blocks = oinfo->oi_policy.l_extent.end;
        oinfo->oi_oa->o_valid |= OBD_MD_FLSIZE | OBD_MD_FLBLOCKS;
        return osc_punch_base(exp, oinfo,
                              oinfo->oi_cb_up, oinfo, rqset);
}

static int osc_sync_interpret(const struct lu_env *env,
                              struct ptlrpc_request *req,
                              void *arg, int rc)
{
        struct osc_async_args *aa = arg;
        struct ost_body *body;
        ENTRY;

        if (rc)
                GOTO(out, rc);

        body = req_capsule_server_get(&req->rq_pill, &RMF_OST_BODY);
        if (body == NULL) {
                CERROR ("can't unpack ost_body\n");
                GOTO(out, rc = -EPROTO);
        }

        *aa->aa_oi->oi_oa = body->oa;
out:
        rc = aa->aa_oi->oi_cb_up(aa->aa_oi, rc);
        RETURN(rc);
}

static int osc_sync(struct obd_export *exp, struct obd_info *oinfo,
                    obd_size start, obd_size end,
                    struct ptlrpc_request_set *set)
{
        struct ptlrpc_request *req;
        struct ost_body       *body;
        struct osc_async_args *aa;
        int                    rc;
        ENTRY;

        if (!oinfo->oi_oa) {
                CDEBUG(D_INFO, "oa NULL\n");
                RETURN(-EINVAL);
        }

        req = ptlrpc_request_alloc(class_exp2cliimp(exp), &RQF_OST_SYNC);
        if (req == NULL)
                RETURN(-ENOMEM);

        osc_set_capa_size(req, &RMF_CAPA1, oinfo->oi_capa);
        rc = ptlrpc_request_pack(req, LUSTRE_OST_VERSION, OST_SYNC);
        if (rc) {
                ptlrpc_request_free(req);
                RETURN(rc);
        }

        /* overload the size and blocks fields in the oa with start/end */
        body = req_capsule_client_get(&req->rq_pill, &RMF_OST_BODY);
        LASSERT(body);
        lustre_set_wire_obdo(&body->oa, oinfo->oi_oa);
        body->oa.o_size = start;
        body->oa.o_blocks = end;
        body->oa.o_valid |= (OBD_MD_FLSIZE | OBD_MD_FLBLOCKS);
        osc_pack_capa(req, body, oinfo->oi_capa);

        ptlrpc_request_set_replen(req);
        req->rq_interpret_reply = osc_sync_interpret;

        CLASSERT(sizeof(*aa) <= sizeof(req->rq_async_args));
        aa = ptlrpc_req_async_args(req);
        aa->aa_oi = oinfo;

        ptlrpc_set_add_req(set, req);
        RETURN (0);
}

/* Find and cancel locally locks matched by @mode in the resource found by
 * @objid. Found locks are added into @cancel list. Returns the amount of
 * locks added to @cancels list. */
static int osc_resource_get_unused(struct obd_export *exp, struct obdo *oa,
                                   cfs_list_t *cancels,
                                   ldlm_mode_t mode, int lock_flags)
{
        struct ldlm_namespace *ns = exp->exp_obd->obd_namespace;
        struct ldlm_res_id res_id;
        struct ldlm_resource *res;
        int count;
        ENTRY;

        osc_build_res_name(oa->o_id, oa->o_seq, &res_id);
        res = ldlm_resource_get(ns, NULL, &res_id, 0, 0);
        if (res == NULL)
                RETURN(0);

        LDLM_RESOURCE_ADDREF(res);
        count = ldlm_cancel_resource_local(res, cancels, NULL, mode,
                                           lock_flags, 0, NULL);
        LDLM_RESOURCE_DELREF(res);
        ldlm_resource_putref(res);
        RETURN(count);
}

static int osc_destroy_interpret(const struct lu_env *env,
                                 struct ptlrpc_request *req, void *data,
                                 int rc)
{
        struct client_obd *cli = &req->rq_import->imp_obd->u.cli;

        cfs_atomic_dec(&cli->cl_destroy_in_flight);
        cfs_waitq_signal(&cli->cl_destroy_waitq);
        return 0;
}

static int osc_can_send_destroy(struct client_obd *cli)
{
        if (cfs_atomic_inc_return(&cli->cl_destroy_in_flight) <=
            cli->cl_max_rpcs_in_flight) {
                /* The destroy request can be sent */
                return 1;
        }
        if (cfs_atomic_dec_return(&cli->cl_destroy_in_flight) <
            cli->cl_max_rpcs_in_flight) {
                /*
                 * The counter has been modified between the two atomic
                 * operations.
                 */
                cfs_waitq_signal(&cli->cl_destroy_waitq);
        }
        return 0;
}

/* Destroy requests can be async always on the client, and we don't even really
 * care about the return code since the client cannot do anything at all about
 * a destroy failure.
 * When the MDS is unlinking a filename, it saves the file objects into a
 * recovery llog, and these object records are cancelled when the OST reports
 * they were destroyed and sync'd to disk (i.e. transaction committed).
 * If the client dies, or the OST is down when the object should be destroyed,
 * the records are not cancelled, and when the OST reconnects to the MDS next,
 * it will retrieve the llog unlink logs and then sends the log cancellation
 * cookies to the MDS after committing destroy transactions. */
static int osc_destroy(struct obd_export *exp, struct obdo *oa,
                       struct lov_stripe_md *ea, struct obd_trans_info *oti,
                       struct obd_export *md_export, void *capa)
{
        struct client_obd     *cli = &exp->exp_obd->u.cli;
        struct ptlrpc_request *req;
        struct ost_body       *body;
        CFS_LIST_HEAD(cancels);
        int rc, count;
        ENTRY;

        if (!oa) {
                CDEBUG(D_INFO, "oa NULL\n");
                RETURN(-EINVAL);
        }

        count = osc_resource_get_unused(exp, oa, &cancels, LCK_PW,
                                        LDLM_FL_DISCARD_DATA);

        req = ptlrpc_request_alloc(class_exp2cliimp(exp), &RQF_OST_DESTROY);
        if (req == NULL) {
                ldlm_lock_list_put(&cancels, l_bl_ast, count);
                RETURN(-ENOMEM);
        }

        osc_set_capa_size(req, &RMF_CAPA1, (struct obd_capa *)capa);
        rc = ldlm_prep_elc_req(exp, req, LUSTRE_OST_VERSION, OST_DESTROY,
                               0, &cancels, count);
        if (rc) {
                ptlrpc_request_free(req);
                RETURN(rc);
        }

        req->rq_request_portal = OST_IO_PORTAL; /* bug 7198 */
        ptlrpc_at_set_req_timeout(req);

        if (oti != NULL && oa->o_valid & OBD_MD_FLCOOKIE)
                oa->o_lcookie = *oti->oti_logcookies;
        body = req_capsule_client_get(&req->rq_pill, &RMF_OST_BODY);
        LASSERT(body);
        lustre_set_wire_obdo(&body->oa, oa);

        osc_pack_capa(req, body, (struct obd_capa *)capa);
        ptlrpc_request_set_replen(req);

        /* don't throttle destroy RPCs for the MDT */
        if (!(cli->cl_import->imp_connect_flags_orig & OBD_CONNECT_MDS)) {
                req->rq_interpret_reply = osc_destroy_interpret;
                if (!osc_can_send_destroy(cli)) {
                        struct l_wait_info lwi = LWI_INTR(LWI_ON_SIGNAL_NOOP,
                                                          NULL);

                        /*
                         * Wait until the number of on-going destroy RPCs drops
                         * under max_rpc_in_flight
                         */
                        l_wait_event_exclusive(cli->cl_destroy_waitq,
                                               osc_can_send_destroy(cli), &lwi);
                }
        }

        /* Do not wait for response */
        ptlrpcd_add_req(req, PSCOPE_OTHER);
        RETURN(0);
}

static void osc_announce_cached(struct client_obd *cli, struct obdo *oa,
                                long writing_bytes)
{
        obd_flag bits = OBD_MD_FLBLOCKS|OBD_MD_FLGRANT;

        LASSERT(!(oa->o_valid & bits));

        oa->o_valid |= bits;
        client_obd_list_lock(&cli->cl_loi_list_lock);
        oa->o_dirty = cli->cl_dirty;
        if (cli->cl_dirty - cli->cl_dirty_transit > cli->cl_dirty_max) {
                CERROR("dirty %lu - %lu > dirty_max %lu\n",
                       cli->cl_dirty, cli->cl_dirty_transit, cli->cl_dirty_max);
                oa->o_undirty = 0;
        } else if (cfs_atomic_read(&obd_dirty_pages) -
                   cfs_atomic_read(&obd_dirty_transit_pages) >
                   obd_max_dirty_pages + 1){
                /* The cfs_atomic_read() allowing the cfs_atomic_inc() are
                 * not covered by a lock thus they may safely race and trip
                 * this CERROR() unless we add in a small fudge factor (+1). */
                CERROR("dirty %d - %d > system dirty_max %d\n",
                       cfs_atomic_read(&obd_dirty_pages),
                       cfs_atomic_read(&obd_dirty_transit_pages),
                       obd_max_dirty_pages);
                oa->o_undirty = 0;
        } else if (cli->cl_dirty_max - cli->cl_dirty > 0x7fffffff) {
                CERROR("dirty %lu - dirty_max %lu too big???\n",
                       cli->cl_dirty, cli->cl_dirty_max);
                oa->o_undirty = 0;
        } else {
                long max_in_flight = (cli->cl_max_pages_per_rpc << CFS_PAGE_SHIFT)*
                                (cli->cl_max_rpcs_in_flight + 1);
                oa->o_undirty = max(cli->cl_dirty_max, max_in_flight);
        }
        oa->o_grant = cli->cl_avail_grant;
        oa->o_dropped = cli->cl_lost_grant;
        cli->cl_lost_grant = 0;
        client_obd_list_unlock(&cli->cl_loi_list_lock);
        CDEBUG(D_CACHE,"dirty: "LPU64" undirty: %u dropped %u grant: "LPU64"\n",
               oa->o_dirty, oa->o_undirty, oa->o_dropped, oa->o_grant);

}

static void osc_update_next_shrink(struct client_obd *cli)
{
        cli->cl_next_shrink_grant =
                cfs_time_shift(cli->cl_grant_shrink_interval);
        CDEBUG(D_CACHE, "next time %ld to shrink grant \n",
               cli->cl_next_shrink_grant);
}

/* caller must hold loi_list_lock */
static void osc_consume_write_grant(struct client_obd *cli,
                                    struct brw_page *pga)
{
        LASSERT_SPIN_LOCKED(&cli->cl_loi_list_lock.lock);
        LASSERT(!(pga->flag & OBD_BRW_FROM_GRANT));
        cfs_atomic_inc(&obd_dirty_pages);
        cli->cl_dirty += CFS_PAGE_SIZE;
        cli->cl_avail_grant -= CFS_PAGE_SIZE;
        pga->flag |= OBD_BRW_FROM_GRANT;
        CDEBUG(D_CACHE, "using %lu grant credits for brw %p page %p\n",
               CFS_PAGE_SIZE, pga, pga->pg);
        LASSERT(cli->cl_avail_grant >= 0);
        osc_update_next_shrink(cli);
}

/* the companion to osc_consume_write_grant, called when a brw has completed.
 * must be called with the loi lock held. */
static void osc_release_write_grant(struct client_obd *cli,
                                    struct brw_page *pga, int sent)
{
        int blocksize = cli->cl_import->imp_obd->obd_osfs.os_bsize ? : 4096;
        ENTRY;

        LASSERT_SPIN_LOCKED(&cli->cl_loi_list_lock.lock);
        if (!(pga->flag & OBD_BRW_FROM_GRANT)) {
                EXIT;
                return;
        }

        pga->flag &= ~OBD_BRW_FROM_GRANT;
        cfs_atomic_dec(&obd_dirty_pages);
        cli->cl_dirty -= CFS_PAGE_SIZE;
        if (pga->flag & OBD_BRW_NOCACHE) {
                pga->flag &= ~OBD_BRW_NOCACHE;
                cfs_atomic_dec(&obd_dirty_transit_pages);
                cli->cl_dirty_transit -= CFS_PAGE_SIZE;
        }
        if (!sent) {
                cli->cl_lost_grant += CFS_PAGE_SIZE;
                CDEBUG(D_CACHE, "lost grant: %lu avail grant: %lu dirty: %lu\n",
                       cli->cl_lost_grant, cli->cl_avail_grant, cli->cl_dirty);
        } else if (CFS_PAGE_SIZE != blocksize && pga->count != CFS_PAGE_SIZE) {
                /* For short writes we shouldn't count parts of pages that
                 * span a whole block on the OST side, or our accounting goes
                 * wrong.  Should match the code in filter_grant_check. */
                int offset = pga->off & ~CFS_PAGE_MASK;
                int count = pga->count + (offset & (blocksize - 1));
                int end = (offset + pga->count) & (blocksize - 1);
                if (end)
                        count += blocksize - end;

                cli->cl_lost_grant += CFS_PAGE_SIZE - count;
                CDEBUG(D_CACHE, "lost %lu grant: %lu avail: %lu dirty: %lu\n",
                       CFS_PAGE_SIZE - count, cli->cl_lost_grant,
                       cli->cl_avail_grant, cli->cl_dirty);
        }

        EXIT;
}

static unsigned long rpcs_in_flight(struct client_obd *cli)
{
        return cli->cl_r_in_flight + cli->cl_w_in_flight;
}

/* caller must hold loi_list_lock */
void osc_wake_cache_waiters(struct client_obd *cli)
{
        cfs_list_t *l, *tmp;
        struct osc_cache_waiter *ocw;

        ENTRY;
        cfs_list_for_each_safe(l, tmp, &cli->cl_cache_waiters) {
                /* if we can't dirty more, we must wait until some is written */
                if ((cli->cl_dirty + CFS_PAGE_SIZE > cli->cl_dirty_max) ||
                   (cfs_atomic_read(&obd_dirty_pages) + 1 >
                    obd_max_dirty_pages)) {
                        CDEBUG(D_CACHE, "no dirty room: dirty: %ld "
                               "osc max %ld, sys max %d\n", cli->cl_dirty,
                               cli->cl_dirty_max, obd_max_dirty_pages);
                        return;
                }

                /* if still dirty cache but no grant wait for pending RPCs that
                 * may yet return us some grant before doing sync writes */
                if (cli->cl_w_in_flight && cli->cl_avail_grant < CFS_PAGE_SIZE) {
                        CDEBUG(D_CACHE, "%u BRW writes in flight, no grant\n",
                               cli->cl_w_in_flight);
                        return;
                }

                ocw = cfs_list_entry(l, struct osc_cache_waiter, ocw_entry);
                cfs_list_del_init(&ocw->ocw_entry);
                if (cli->cl_avail_grant < CFS_PAGE_SIZE) {
                        /* no more RPCs in flight to return grant, do sync IO */
                        ocw->ocw_rc = -EDQUOT;
                        CDEBUG(D_INODE, "wake oap %p for sync\n", ocw->ocw_oap);
                } else {
                        osc_consume_write_grant(cli,
                                                &ocw->ocw_oap->oap_brw_page);
                }

                cfs_waitq_signal(&ocw->ocw_waitq);
        }

        EXIT;
}

static void __osc_update_grant(struct client_obd *cli, obd_size grant)
{
        client_obd_list_lock(&cli->cl_loi_list_lock);
        cli->cl_avail_grant += grant;
        client_obd_list_unlock(&cli->cl_loi_list_lock);
}

static void osc_update_grant(struct client_obd *cli, struct ost_body *body)
{
        if (body->oa.o_valid & OBD_MD_FLGRANT) {
                CDEBUG(D_CACHE, "got "LPU64" extra grant\n", body->oa.o_grant);
                __osc_update_grant(cli, body->oa.o_grant);
        }
}

static int osc_set_info_async(struct obd_export *exp, obd_count keylen,
                              void *key, obd_count vallen, void *val,
                              struct ptlrpc_request_set *set);

static int osc_shrink_grant_interpret(const struct lu_env *env,
                                      struct ptlrpc_request *req,
                                      void *aa, int rc)
{
        struct client_obd *cli = &req->rq_import->imp_obd->u.cli;
        struct obdo *oa = ((struct osc_grant_args *)aa)->aa_oa;
        struct ost_body *body;

        if (rc != 0) {
                __osc_update_grant(cli, oa->o_grant);
                GOTO(out, rc);
        }

        body = req_capsule_server_get(&req->rq_pill, &RMF_OST_BODY);
        LASSERT(body);
        osc_update_grant(cli, body);
out:
        OBDO_FREE(oa);
        return rc;
}

static void osc_shrink_grant_local(struct client_obd *cli, struct obdo *oa)
{
        client_obd_list_lock(&cli->cl_loi_list_lock);
        oa->o_grant = cli->cl_avail_grant / 4;
        cli->cl_avail_grant -= oa->o_grant;
        client_obd_list_unlock(&cli->cl_loi_list_lock);
        if (!(oa->o_valid & OBD_MD_FLFLAGS)) {
                oa->o_valid |= OBD_MD_FLFLAGS;
                oa->o_flags = 0;
        }
        oa->o_flags |= OBD_FL_SHRINK_GRANT;
        osc_update_next_shrink(cli);
}

/* Shrink the current grant, either from some large amount to enough for a
 * full set of in-flight RPCs, or if we have already shrunk to that limit
 * then to enough for a single RPC.  This avoids keeping more grant than
 * needed, and avoids shrinking the grant piecemeal. */
static int osc_shrink_grant(struct client_obd *cli)
{
        long target = (cli->cl_max_rpcs_in_flight + 1) *
                      cli->cl_max_pages_per_rpc;

        client_obd_list_lock(&cli->cl_loi_list_lock);
        if (cli->cl_avail_grant <= target)
                target = cli->cl_max_pages_per_rpc;
        client_obd_list_unlock(&cli->cl_loi_list_lock);

        return osc_shrink_grant_to_target(cli, target);
}

int osc_shrink_grant_to_target(struct client_obd *cli, long target)
{
        int    rc = 0;
        struct ost_body     *body;
        ENTRY;

        client_obd_list_lock(&cli->cl_loi_list_lock);
        /* Don't shrink if we are already above or below the desired limit
         * We don't want to shrink below a single RPC, as that will negatively
         * impact block allocation and long-term performance. */
        if (target < cli->cl_max_pages_per_rpc)
                target = cli->cl_max_pages_per_rpc;

        if (target >= cli->cl_avail_grant) {
                client_obd_list_unlock(&cli->cl_loi_list_lock);
                RETURN(0);
        }
        client_obd_list_unlock(&cli->cl_loi_list_lock);

        OBD_ALLOC_PTR(body);
        if (!body)
                RETURN(-ENOMEM);

        osc_announce_cached(cli, &body->oa, 0);

        client_obd_list_lock(&cli->cl_loi_list_lock);
        body->oa.o_grant = cli->cl_avail_grant - target;
        cli->cl_avail_grant = target;
        client_obd_list_unlock(&cli->cl_loi_list_lock);
        if (!(body->oa.o_valid & OBD_MD_FLFLAGS)) {
                body->oa.o_valid |= OBD_MD_FLFLAGS;
                body->oa.o_flags = 0;
        }
        body->oa.o_flags |= OBD_FL_SHRINK_GRANT;
        osc_update_next_shrink(cli);

        rc = osc_set_info_async(cli->cl_import->imp_obd->obd_self_export,
                                sizeof(KEY_GRANT_SHRINK), KEY_GRANT_SHRINK,
                                sizeof(*body), body, NULL);
        if (rc != 0)
                __osc_update_grant(cli, body->oa.o_grant);
        OBD_FREE_PTR(body);
        RETURN(rc);
}

#define GRANT_SHRINK_LIMIT PTLRPC_MAX_BRW_SIZE
static int osc_should_shrink_grant(struct client_obd *client)
{
        cfs_time_t time = cfs_time_current();
        cfs_time_t next_shrink = client->cl_next_shrink_grant;

        if ((client->cl_import->imp_connect_data.ocd_connect_flags &
             OBD_CONNECT_GRANT_SHRINK) == 0)
                return 0;

        if (cfs_time_aftereq(time, next_shrink - 5 * CFS_TICK)) {
                if (client->cl_import->imp_state == LUSTRE_IMP_FULL &&
                    client->cl_avail_grant > GRANT_SHRINK_LIMIT)
                        return 1;
                else
                        osc_update_next_shrink(client);
        }
        return 0;
}

static int osc_grant_shrink_grant_cb(struct timeout_item *item, void *data)
{
        struct client_obd *client;

        cfs_list_for_each_entry(client, &item->ti_obd_list,
                                cl_grant_shrink_list) {
                if (osc_should_shrink_grant(client))
                        osc_shrink_grant(client);
        }
        return 0;
}

static int osc_add_shrink_grant(struct client_obd *client)
{
        int rc;

        rc = ptlrpc_add_timeout_client(client->cl_grant_shrink_interval,
                                       TIMEOUT_GRANT,
                                       osc_grant_shrink_grant_cb, NULL,
                                       &client->cl_grant_shrink_list);
        if (rc) {
                CERROR("add grant client %s error %d\n",
                        client->cl_import->imp_obd->obd_name, rc);
                return rc;
        }
        CDEBUG(D_CACHE, "add grant client %s \n",
               client->cl_import->imp_obd->obd_name);
        osc_update_next_shrink(client);
        return 0;
}

static int osc_del_shrink_grant(struct client_obd *client)
{
        return ptlrpc_del_timeout_client(&client->cl_grant_shrink_list,
                                         TIMEOUT_GRANT);
}

static void osc_init_grant(struct client_obd *cli, struct obd_connect_data *ocd)
{
        /*
         * ocd_grant is the total grant amount we're expect to hold: if we've
         * been evicted, it's the new avail_grant amount, cl_dirty will drop
         * to 0 as inflight RPCs fail out; otherwise, it's avail_grant + dirty.
         *
         * race is tolerable here: if we're evicted, but imp_state already
         * left EVICTED state, then cl_dirty must be 0 already.
         */
        client_obd_list_lock(&cli->cl_loi_list_lock);
        if (cli->cl_import->imp_state == LUSTRE_IMP_EVICTED)
                cli->cl_avail_grant = ocd->ocd_grant;
        else
                cli->cl_avail_grant = ocd->ocd_grant - cli->cl_dirty;

        if (cli->cl_avail_grant < 0) {
                CWARN("%s: available grant < 0, the OSS is probably not running"
                      " with patch from bug20278 (%ld) \n",
                      cli->cl_import->imp_obd->obd_name, cli->cl_avail_grant);
                /* workaround for 1.6 servers which do not have
                 * the patch from bug20278 */
                cli->cl_avail_grant = ocd->ocd_grant;
        }

        client_obd_list_unlock(&cli->cl_loi_list_lock);

        CDEBUG(D_CACHE, "%s, setting cl_avail_grant: %ld cl_lost_grant: %ld \n",
               cli->cl_import->imp_obd->obd_name,
               cli->cl_avail_grant, cli->cl_lost_grant);

        if (ocd->ocd_connect_flags & OBD_CONNECT_GRANT_SHRINK &&
            cfs_list_empty(&cli->cl_grant_shrink_list))
                osc_add_shrink_grant(cli);
}

/* We assume that the reason this OSC got a short read is because it read
 * beyond the end of a stripe file; i.e. lustre is reading a sparse file
 * via the LOV, and it _knows_ it's reading inside the file, it's just that
 * this stripe never got written at or beyond this stripe offset yet. */
static void handle_short_read(int nob_read, obd_count page_count,
                              struct brw_page **pga)
{
        char *ptr;
        int i = 0;

        /* skip bytes read OK */
        while (nob_read > 0) {
                LASSERT (page_count > 0);

                if (pga[i]->count > nob_read) {
                        /* EOF inside this page */
                        ptr = cfs_kmap(pga[i]->pg) +
                                (pga[i]->off & ~CFS_PAGE_MASK);
                        memset(ptr + nob_read, 0, pga[i]->count - nob_read);
                        cfs_kunmap(pga[i]->pg);
                        page_count--;
                        i++;
                        break;
                }

                nob_read -= pga[i]->count;
                page_count--;
                i++;
        }

        /* zero remaining pages */
        while (page_count-- > 0) {
                ptr = cfs_kmap(pga[i]->pg) + (pga[i]->off & ~CFS_PAGE_MASK);
                memset(ptr, 0, pga[i]->count);
                cfs_kunmap(pga[i]->pg);
                i++;
        }
}

static int check_write_rcs(struct ptlrpc_request *req,
                           int requested_nob, int niocount,
                           obd_count page_count, struct brw_page **pga)
{
        int     i;
        __u32   *remote_rcs;

        remote_rcs = req_capsule_server_sized_get(&req->rq_pill, &RMF_RCS,
                                                  sizeof(*remote_rcs) *
                                                  niocount);
        if (remote_rcs == NULL) {
                CDEBUG(D_INFO, "Missing/short RC vector on BRW_WRITE reply\n");
                return(-EPROTO);
        }

        /* return error if any niobuf was in error */
        for (i = 0; i < niocount; i++) {
                if ((int)remote_rcs[i] < 0)
                        return(remote_rcs[i]);

                if (remote_rcs[i] != 0) {
                        CDEBUG(D_INFO, "rc[%d] invalid (%d) req %p\n",
                                i, remote_rcs[i], req);
                        return(-EPROTO);
                }
        }

        if (req->rq_bulk->bd_nob_transferred != requested_nob) {
                CERROR("Unexpected # bytes transferred: %d (requested %d)\n",
                       req->rq_bulk->bd_nob_transferred, requested_nob);
                return(-EPROTO);
        }

        return (0);
}

static inline int can_merge_pages(struct brw_page *p1, struct brw_page *p2)
{
        if (p1->flag != p2->flag) {
                unsigned mask = ~(OBD_BRW_FROM_GRANT|
                                  OBD_BRW_NOCACHE|OBD_BRW_SYNC|OBD_BRW_ASYNC);

                /* warn if we try to combine flags that we don't know to be
                 * safe to combine */
                if ((p1->flag & mask) != (p2->flag & mask))
                        CERROR("is it ok to have flags 0x%x and 0x%x in the "
                               "same brw?\n", p1->flag, p2->flag);
                return 0;
        }

        return (p1->off + p1->count == p2->off);
}

static obd_count osc_checksum_bulk(int nob, obd_count pg_count,
                                   struct brw_page **pga, int opc,
                                   cksum_type_t cksum_type)
{
        __u32 cksum;
        int i = 0;

        LASSERT (pg_count > 0);
        cksum = init_checksum(cksum_type);
        while (nob > 0 && pg_count > 0) {
                unsigned char *ptr = cfs_kmap(pga[i]->pg);
                int off = pga[i]->off & ~CFS_PAGE_MASK;
                int count = pga[i]->count > nob ? nob : pga[i]->count;

                /* corrupt the data before we compute the checksum, to
                 * simulate an OST->client data error */
                if (i == 0 && opc == OST_READ &&
                    OBD_FAIL_CHECK(OBD_FAIL_OSC_CHECKSUM_RECEIVE))
                        memcpy(ptr + off, "bad1", min(4, nob));
                cksum = compute_checksum(cksum, ptr + off, count, cksum_type);
                cfs_kunmap(pga[i]->pg);
                LL_CDEBUG_PAGE(D_PAGE, pga[i]->pg, "off %d checksum %x\n",
                               off, cksum);

                nob -= pga[i]->count;
                pg_count--;
                i++;
        }
        /* For sending we only compute the wrong checksum instead
         * of corrupting the data so it is still correct on a redo */
        if (opc == OST_WRITE && OBD_FAIL_CHECK(OBD_FAIL_OSC_CHECKSUM_SEND))
                cksum++;

        return cksum;
}

static int osc_brw_prep_request(int cmd, struct client_obd *cli,struct obdo *oa,
                                struct lov_stripe_md *lsm, obd_count page_count,
                                struct brw_page **pga,
                                struct ptlrpc_request **reqp,
                                struct obd_capa *ocapa, int reserve,
                                int resend)
{
        struct ptlrpc_request   *req;
        struct ptlrpc_bulk_desc *desc;
        struct ost_body         *body;
        struct obd_ioobj        *ioobj;
        struct niobuf_remote    *niobuf;
        int niocount, i, requested_nob, opc, rc;
        struct osc_brw_async_args *aa;
        struct req_capsule      *pill;
        struct brw_page *pg_prev;

        ENTRY;
        if (OBD_FAIL_CHECK(OBD_FAIL_OSC_BRW_PREP_REQ))
                RETURN(-ENOMEM); /* Recoverable */
        if (OBD_FAIL_CHECK(OBD_FAIL_OSC_BRW_PREP_REQ2))
                RETURN(-EINVAL); /* Fatal */

        if ((cmd & OBD_BRW_WRITE) != 0) {
                opc = OST_WRITE;
                req = ptlrpc_request_alloc_pool(cli->cl_import,
                                                cli->cl_import->imp_rq_pool,
                                                &RQF_OST_BRW_WRITE);
        } else {
                opc = OST_READ;
                req = ptlrpc_request_alloc(cli->cl_import, &RQF_OST_BRW_READ);
        }
        if (req == NULL)
                RETURN(-ENOMEM);

        for (niocount = i = 1; i < page_count; i++) {
                if (!can_merge_pages(pga[i - 1], pga[i]))
                        niocount++;
        }

        pill = &req->rq_pill;
        req_capsule_set_size(pill, &RMF_OBD_IOOBJ, RCL_CLIENT,
                             sizeof(*ioobj));
        req_capsule_set_size(pill, &RMF_NIOBUF_REMOTE, RCL_CLIENT,
                             niocount * sizeof(*niobuf));
        osc_set_capa_size(req, &RMF_CAPA1, ocapa);

        rc = ptlrpc_request_pack(req, LUSTRE_OST_VERSION, opc);
        if (rc) {
                ptlrpc_request_free(req);
                RETURN(rc);
        }
        req->rq_request_portal = OST_IO_PORTAL; /* bug 7198 */
        ptlrpc_at_set_req_timeout(req);

        if (opc == OST_WRITE)
                desc = ptlrpc_prep_bulk_imp(req, page_count,
                                            BULK_GET_SOURCE, OST_BULK_PORTAL);
        else
                desc = ptlrpc_prep_bulk_imp(req, page_count,
                                            BULK_PUT_SINK, OST_BULK_PORTAL);

        if (desc == NULL)
                GOTO(out, rc = -ENOMEM);
        /* NB request now owns desc and will free it when it gets freed */

        body = req_capsule_client_get(pill, &RMF_OST_BODY);
        ioobj = req_capsule_client_get(pill, &RMF_OBD_IOOBJ);
        niobuf = req_capsule_client_get(pill, &RMF_NIOBUF_REMOTE);
        LASSERT(body != NULL && ioobj != NULL && niobuf != NULL);

        lustre_set_wire_obdo(&body->oa, oa);

        obdo_to_ioobj(oa, ioobj);
        ioobj->ioo_bufcnt = niocount;
        osc_pack_capa(req, body, ocapa);
        LASSERT (page_count > 0);
        pg_prev = pga[0];
        for (requested_nob = i = 0; i < page_count; i++, niobuf++) {
                struct brw_page *pg = pga[i];
                int poff = pg->off & ~CFS_PAGE_MASK;

                LASSERT(pg->count > 0);
                /* make sure there is no gap in the middle of page array */
                LASSERTF(page_count == 1 ||
                         (ergo(i == 0, poff + pg->count == CFS_PAGE_SIZE) &&
                          ergo(i > 0 && i < page_count - 1,
                               poff == 0 && pg->count == CFS_PAGE_SIZE)   &&
                          ergo(i == page_count - 1, poff == 0)),
                         "i: %d/%d pg: %p off: "LPU64", count: %u\n",
                         i, page_count, pg, pg->off, pg->count);
#ifdef __linux__
                LASSERTF(i == 0 || pg->off > pg_prev->off,
                         "i %d p_c %u pg %p [pri %lu ind %lu] off "LPU64
                         " prev_pg %p [pri %lu ind %lu] off "LPU64"\n",
                         i, page_count,
                         pg->pg, page_private(pg->pg), pg->pg->index, pg->off,
                         pg_prev->pg, page_private(pg_prev->pg),
                         pg_prev->pg->index, pg_prev->off);
#else
                LASSERTF(i == 0 || pg->off > pg_prev->off,
                         "i %d p_c %u\n", i, page_count);
#endif
                LASSERT((pga[0]->flag & OBD_BRW_SRVLOCK) ==
                        (pg->flag & OBD_BRW_SRVLOCK));

                ptlrpc_prep_bulk_page(desc, pg->pg, poff, pg->count);
                requested_nob += pg->count;

                if (i > 0 && can_merge_pages(pg_prev, pg)) {
                        niobuf--;
                        niobuf->len += pg->count;
                } else {
                        niobuf->offset = pg->off;
                        niobuf->len    = pg->count;
                        niobuf->flags  = pg->flag;
                }
                pg_prev = pg;
        }

        LASSERTF((void *)(niobuf - niocount) ==
                req_capsule_client_get(&req->rq_pill, &RMF_NIOBUF_REMOTE),
                "want %p - real %p\n", req_capsule_client_get(&req->rq_pill,
                &RMF_NIOBUF_REMOTE), (void *)(niobuf - niocount));

        osc_announce_cached(cli, &body->oa, opc == OST_WRITE ? requested_nob:0);
        if (resend) {
                if ((body->oa.o_valid & OBD_MD_FLFLAGS) == 0) {
                        body->oa.o_valid |= OBD_MD_FLFLAGS;
                        body->oa.o_flags = 0;
                }
                body->oa.o_flags |= OBD_FL_RECOV_RESEND;
        }

        if (osc_should_shrink_grant(cli))
                osc_shrink_grant_local(cli, &body->oa);

        /* size[REQ_REC_OFF] still sizeof (*body) */
        if (opc == OST_WRITE) {
                if (unlikely(cli->cl_checksum) &&
                    !sptlrpc_flavor_has_bulk(&req->rq_flvr)) {
                        /* store cl_cksum_type in a local variable since
                         * it can be changed via lprocfs */
                        cksum_type_t cksum_type = cli->cl_cksum_type;

                        if ((body->oa.o_valid & OBD_MD_FLFLAGS) == 0) {
                                oa->o_flags &= OBD_FL_LOCAL_MASK;
                                body->oa.o_flags = 0;
                        }
                        body->oa.o_flags |= cksum_type_pack(cksum_type);
                        body->oa.o_valid |= OBD_MD_FLCKSUM | OBD_MD_FLFLAGS;
                        body->oa.o_cksum = osc_checksum_bulk(requested_nob,
                                                             page_count, pga,
                                                             OST_WRITE,
                                                             cksum_type);
                        CDEBUG(D_PAGE, "checksum at write origin: %x\n",
                               body->oa.o_cksum);
                        /* save this in 'oa', too, for later checking */
                        oa->o_valid |= OBD_MD_FLCKSUM | OBD_MD_FLFLAGS;
                        oa->o_flags |= cksum_type_pack(cksum_type);
                } else {
                        /* clear out the checksum flag, in case this is a
                         * resend but cl_checksum is no longer set. b=11238 */
                        oa->o_valid &= ~OBD_MD_FLCKSUM;
                }
                oa->o_cksum = body->oa.o_cksum;
                /* 1 RC per niobuf */
                req_capsule_set_size(pill, &RMF_RCS, RCL_SERVER,
                                     sizeof(__u32) * niocount);
        } else {
                if (unlikely(cli->cl_checksum) &&
                    !sptlrpc_flavor_has_bulk(&req->rq_flvr)) {
                        if ((body->oa.o_valid & OBD_MD_FLFLAGS) == 0)
                                body->oa.o_flags = 0;
                        body->oa.o_flags |= cksum_type_pack(cli->cl_cksum_type);
                        body->oa.o_valid |= OBD_MD_FLCKSUM | OBD_MD_FLFLAGS;
                }
        }
        ptlrpc_request_set_replen(req);

        CLASSERT(sizeof(*aa) <= sizeof(req->rq_async_args));
        aa = ptlrpc_req_async_args(req);
        aa->aa_oa = oa;
        aa->aa_requested_nob = requested_nob;
        aa->aa_nio_count = niocount;
        aa->aa_page_count = page_count;
        aa->aa_resends = 0;
        aa->aa_ppga = pga;
        aa->aa_cli = cli;
        CFS_INIT_LIST_HEAD(&aa->aa_oaps);
        if (ocapa && reserve)
                aa->aa_ocapa = capa_get(ocapa);

        *reqp = req;
        RETURN(0);

 out:
        ptlrpc_req_finished(req);
        RETURN(rc);
}

static int check_write_checksum(struct obdo *oa, const lnet_process_id_t *peer,
                                __u32 client_cksum, __u32 server_cksum, int nob,
                                obd_count page_count, struct brw_page **pga,
                                cksum_type_t client_cksum_type)
{
        __u32 new_cksum;
        char *msg;
        cksum_type_t cksum_type;

        if (server_cksum == client_cksum) {
                CDEBUG(D_PAGE, "checksum %x confirmed\n", client_cksum);
                return 0;
        }

        /* If this is mmaped file - it can be changed at any time */
        if (oa->o_valid & OBD_MD_FLFLAGS && oa->o_flags & OBD_FL_MMAP)
                return 1;

        if (oa->o_valid & OBD_MD_FLFLAGS)
                cksum_type = cksum_type_unpack(oa->o_flags);
        else
                cksum_type = OBD_CKSUM_CRC32;

        new_cksum = osc_checksum_bulk(nob, page_count, pga, OST_WRITE,
                                      cksum_type);

        if (cksum_type != client_cksum_type)
                msg = "the server did not use the checksum type specified in "
                      "the original request - likely a protocol problem";
        else if (new_cksum == server_cksum)
                msg = "changed on the client after we checksummed it - "
                      "likely false positive due to mmap IO (bug 11742)";
        else if (new_cksum == client_cksum)
                msg = "changed in transit before arrival at OST";
        else
                msg = "changed in transit AND doesn't match the original - "
                      "likely false positive due to mmap IO (bug 11742)";

        LCONSOLE_ERROR_MSG(0x132, "BAD WRITE CHECKSUM: %s: from %s inode "DFID
                           " object "LPU64"/"LPU64" extent ["LPU64"-"LPU64"]\n",
                           msg, libcfs_nid2str(peer->nid),
                           oa->o_valid & OBD_MD_FLFID ? oa->o_parent_seq : (__u64)0,
                           oa->o_valid & OBD_MD_FLFID ? oa->o_parent_oid : 0,
                           oa->o_valid & OBD_MD_FLFID ? oa->o_parent_ver : 0,
                           oa->o_id,
                           oa->o_valid & OBD_MD_FLGROUP ? oa->o_seq : (__u64)0,
                           pga[0]->off,
                           pga[page_count-1]->off + pga[page_count-1]->count - 1);
        CERROR("original client csum %x (type %x), server csum %x (type %x), "
               "client csum now %x\n", client_cksum, client_cksum_type,
               server_cksum, cksum_type, new_cksum);
        return 1;
}

/* Note rc enters this function as number of bytes transferred */
static int osc_brw_fini_request(struct ptlrpc_request *req, int rc)
{
        struct osc_brw_async_args *aa = (void *)&req->rq_async_args;
        const lnet_process_id_t *peer =
                        &req->rq_import->imp_connection->c_peer;
        struct client_obd *cli = aa->aa_cli;
        struct ost_body *body;
        __u32 client_cksum = 0;
        ENTRY;

        if (rc < 0 && rc != -EDQUOT) {
                DEBUG_REQ(D_INFO, req, "Failed request with rc = %d\n", rc);
                RETURN(rc);
        }

        LASSERTF(req->rq_repmsg != NULL, "rc = %d\n", rc);
        body = req_capsule_server_get(&req->rq_pill, &RMF_OST_BODY);
        if (body == NULL) {
                DEBUG_REQ(D_INFO, req, "Can't unpack body\n");
                RETURN(-EPROTO);
        }

#ifdef HAVE_QUOTA_SUPPORT
        /* set/clear over quota flag for a uid/gid */
        if (lustre_msg_get_opc(req->rq_reqmsg) == OST_WRITE &&
            body->oa.o_valid & (OBD_MD_FLUSRQUOTA | OBD_MD_FLGRPQUOTA)) {
                unsigned int qid[MAXQUOTAS] = { body->oa.o_uid, body->oa.o_gid };

                CDEBUG(D_QUOTA, "setdq for [%u %u] with valid "LPX64", flags %x\n",
                       body->oa.o_uid, body->oa.o_gid, body->oa.o_valid,
                       body->oa.o_flags);
                lquota_setdq(quota_interface, cli, qid, body->oa.o_valid,
                             body->oa.o_flags);
        }
#endif

        osc_update_grant(cli, body);

        if (rc < 0)
                RETURN(rc);

        if (aa->aa_oa->o_valid & OBD_MD_FLCKSUM)
                client_cksum = aa->aa_oa->o_cksum; /* save for later */

        if (lustre_msg_get_opc(req->rq_reqmsg) == OST_WRITE) {
                if (rc > 0) {
                        CERROR("Unexpected +ve rc %d\n", rc);
                        RETURN(-EPROTO);
                }
                LASSERT(req->rq_bulk->bd_nob == aa->aa_requested_nob);

                if (sptlrpc_cli_unwrap_bulk_write(req, req->rq_bulk))
                        RETURN(-EAGAIN);

                if ((aa->aa_oa->o_valid & OBD_MD_FLCKSUM) && client_cksum &&
                    check_write_checksum(&body->oa, peer, client_cksum,
                                         body->oa.o_cksum, aa->aa_requested_nob,
                                         aa->aa_page_count, aa->aa_ppga,
                                         cksum_type_unpack(aa->aa_oa->o_flags)))
                        RETURN(-EAGAIN);

                rc = check_write_rcs(req, aa->aa_requested_nob,aa->aa_nio_count,
                                     aa->aa_page_count, aa->aa_ppga);
                GOTO(out, rc);
        }

        /* The rest of this function executes only for OST_READs */

        /* if unwrap_bulk failed, return -EAGAIN to retry */
        rc = sptlrpc_cli_unwrap_bulk_read(req, req->rq_bulk, rc);
        if (rc < 0)
                GOTO(out, rc = -EAGAIN);

        if (rc > aa->aa_requested_nob) {
                CERROR("Unexpected rc %d (%d requested)\n", rc,
                       aa->aa_requested_nob);
                RETURN(-EPROTO);
        }

        if (rc != req->rq_bulk->bd_nob_transferred) {
                CERROR ("Unexpected rc %d (%d transferred)\n",
                        rc, req->rq_bulk->bd_nob_transferred);
                return (-EPROTO);
        }

        if (rc < aa->aa_requested_nob)
                handle_short_read(rc, aa->aa_page_count, aa->aa_ppga);

        if (body->oa.o_valid & OBD_MD_FLCKSUM) {
                static int cksum_counter;
                __u32      server_cksum = body->oa.o_cksum;
                char      *via;
                char      *router;
                cksum_type_t cksum_type;

                if (body->oa.o_valid & OBD_MD_FLFLAGS)
                        cksum_type = cksum_type_unpack(body->oa.o_flags);
                else
                        cksum_type = OBD_CKSUM_CRC32;
                client_cksum = osc_checksum_bulk(rc, aa->aa_page_count,
                                                 aa->aa_ppga, OST_READ,
                                                 cksum_type);

                if (peer->nid == req->rq_bulk->bd_sender) {
                        via = router = "";
                } else {
                        via = " via ";
                        router = libcfs_nid2str(req->rq_bulk->bd_sender);
                }

                if (server_cksum == ~0 && rc > 0) {
                        CERROR("Protocol error: server %s set the 'checksum' "
                               "bit, but didn't send a checksum.  Not fatal, "
                               "but please notify on http://bugs.whamcloud.com/\n",
                               libcfs_nid2str(peer->nid));
                } else if (server_cksum != client_cksum) {
                        LCONSOLE_ERROR_MSG(0x133, "%s: BAD READ CHECKSUM: from "
                                           "%s%s%s inode "DFID" object "
                                           LPU64"/"LPU64" extent "
                                           "["LPU64"-"LPU64"]\n",
                                           req->rq_import->imp_obd->obd_name,
                                           libcfs_nid2str(peer->nid),
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
                                           aa->aa_ppga[0]->off,
                                           aa->aa_ppga[aa->aa_page_count-1]->off +
                                           aa->aa_ppga[aa->aa_page_count-1]->count -
                                                                        1);
                        CERROR("client %x, server %x, cksum_type %x\n",
                               client_cksum, server_cksum, cksum_type);
                        cksum_counter = 0;
                        aa->aa_oa->o_cksum = client_cksum;
                        rc = -EAGAIN;
                } else {
                        cksum_counter++;
                        CDEBUG(D_PAGE, "checksum %x confirmed\n", client_cksum);
                        rc = 0;
                }
        } else if (unlikely(client_cksum)) {
                static int cksum_missed;

                cksum_missed++;
                if ((cksum_missed & (-cksum_missed)) == cksum_missed)
                        CERROR("Checksum %u requested from %s but not sent\n",
                               cksum_missed, libcfs_nid2str(peer->nid));
        } else {
                rc = 0;
        }
out:
        if (rc >= 0)
                lustre_get_wire_obdo(aa->aa_oa, &body->oa);

        RETURN(rc);
}

static int osc_brw_internal(int cmd, struct obd_export *exp, struct obdo *oa,
                            struct lov_stripe_md *lsm,
                            obd_count page_count, struct brw_page **pga,
                            struct obd_capa *ocapa)
{
        struct ptlrpc_request *req;
        int                    rc;
        cfs_waitq_t            waitq;
        int                    resends = 0;
        struct l_wait_info     lwi;

        ENTRY;

        cfs_waitq_init(&waitq);

restart_bulk:
        rc = osc_brw_prep_request(cmd, &exp->exp_obd->u.cli, oa, lsm,
                                  page_count, pga, &req, ocapa, 0, resends);
        if (rc != 0)
                return (rc);

        rc = ptlrpc_queue_wait(req);

        if (rc == -ETIMEDOUT && req->rq_resend) {
                DEBUG_REQ(D_HA, req,  "BULK TIMEOUT");
                ptlrpc_req_finished(req);
                goto restart_bulk;
        }

        rc = osc_brw_fini_request(req, rc);

        ptlrpc_req_finished(req);
        if (osc_recoverable_error(rc)) {
                resends++;
                if (!client_should_resend(resends, &exp->exp_obd->u.cli)) {
                        CERROR("too many resend retries, returning error\n");
                        RETURN(-EIO);
                }

                lwi = LWI_TIMEOUT_INTR(cfs_time_seconds(resends), NULL, NULL, NULL);
                l_wait_event(waitq, 0, &lwi);

                goto restart_bulk;
        }

        RETURN (rc);
}

int osc_brw_redo_request(struct ptlrpc_request *request,
                         struct osc_brw_async_args *aa)
{
        struct ptlrpc_request *new_req;
        struct ptlrpc_request_set *set = request->rq_set;
        struct osc_brw_async_args *new_aa;
        struct osc_async_page *oap;
        int rc = 0;
        ENTRY;

        if (!client_should_resend(aa->aa_resends, aa->aa_cli)) {
                CERROR("too many resent retries, returning error\n");
                RETURN(-EIO);
        }

        DEBUG_REQ(D_ERROR, request, "redo for recoverable error");

        rc = osc_brw_prep_request(lustre_msg_get_opc(request->rq_reqmsg) ==
                                        OST_WRITE ? OBD_BRW_WRITE :OBD_BRW_READ,
                                  aa->aa_cli, aa->aa_oa,
                                  NULL /* lsm unused by osc currently */,
                                  aa->aa_page_count, aa->aa_ppga,
                                  &new_req, aa->aa_ocapa, 0, 1);
        if (rc)
                RETURN(rc);

        client_obd_list_lock(&aa->aa_cli->cl_loi_list_lock);

        cfs_list_for_each_entry(oap, &aa->aa_oaps, oap_rpc_item) {
                if (oap->oap_request != NULL) {
                        LASSERTF(request == oap->oap_request,
                                 "request %p != oap_request %p\n",
                                 request, oap->oap_request);
                        if (oap->oap_interrupted) {
                                client_obd_list_unlock(&aa->aa_cli->cl_loi_list_lock);
                                ptlrpc_req_finished(new_req);
                                RETURN(-EINTR);
                        }
                }
        }
        /* New request takes over pga and oaps from old request.
         * Note that copying a list_head doesn't work, need to move it... */
        aa->aa_resends++;
        new_req->rq_interpret_reply = request->rq_interpret_reply;
        new_req->rq_async_args = request->rq_async_args;
        new_req->rq_sent = cfs_time_current_sec() + aa->aa_resends;

        new_aa = ptlrpc_req_async_args(new_req);

        CFS_INIT_LIST_HEAD(&new_aa->aa_oaps);
        cfs_list_splice(&aa->aa_oaps, &new_aa->aa_oaps);
        CFS_INIT_LIST_HEAD(&aa->aa_oaps);

        cfs_list_for_each_entry(oap, &new_aa->aa_oaps, oap_rpc_item) {
                if (oap->oap_request) {
                        ptlrpc_req_finished(oap->oap_request);
                        oap->oap_request = ptlrpc_request_addref(new_req);
                }
        }

        new_aa->aa_ocapa = aa->aa_ocapa;
        aa->aa_ocapa = NULL;

        /* use ptlrpc_set_add_req is safe because interpret functions work
         * in check_set context. only one way exist with access to request
         * from different thread got -EINTR - this way protected with
         * cl_loi_list_lock */
        ptlrpc_set_add_req(set, new_req);

        client_obd_list_unlock(&aa->aa_cli->cl_loi_list_lock);

        DEBUG_REQ(D_INFO, new_req, "new request");
        RETURN(0);
}

/*
 * ugh, we want disk allocation on the target to happen in offset order.  we'll
 * follow sedgewicks advice and stick to the dead simple shellsort -- it'll do
 * fine for our small page arrays and doesn't require allocation.  its an
 * insertion sort that swaps elements that are strides apart, shrinking the
 * stride down until its '1' and the array is sorted.
 */
static void sort_brw_pages(struct brw_page **array, int num)
{
        int stride, i, j;
        struct brw_page *tmp;

        if (num == 1)
                return;
        for (stride = 1; stride < num ; stride = (stride * 3) + 1)
                ;

        do {
                stride /= 3;
                for (i = stride ; i < num ; i++) {
                        tmp = array[i];
                        j = i;
                        while (j >= stride && array[j - stride]->off > tmp->off) {
                                array[j] = array[j - stride];
                                j -= stride;
                        }
                        array[j] = tmp;
                }
        } while (stride > 1);
}

static obd_count max_unfragmented_pages(struct brw_page **pg, obd_count pages)
{
        int count = 1;
        int offset;
        int i = 0;

        LASSERT (pages > 0);
        offset = pg[i]->off & ~CFS_PAGE_MASK;

        for (;;) {
                pages--;
                if (pages == 0)         /* that's all */
                        return count;

                if (offset + pg[i]->count < CFS_PAGE_SIZE)
                        return count;   /* doesn't end on page boundary */

                i++;
                offset = pg[i]->off & ~CFS_PAGE_MASK;
                if (offset != 0)        /* doesn't start on page boundary */
                        return count;

                count++;
        }
}

static struct brw_page **osc_build_ppga(struct brw_page *pga, obd_count count)
{
        struct brw_page **ppga;
        int i;

        OBD_ALLOC(ppga, sizeof(*ppga) * count);
        if (ppga == NULL)
                return NULL;

        for (i = 0; i < count; i++)
                ppga[i] = pga + i;
        return ppga;
}

static void osc_release_ppga(struct brw_page **ppga, obd_count count)
{
        LASSERT(ppga != NULL);
        OBD_FREE(ppga, sizeof(*ppga) * count);
}

static int osc_brw(int cmd, struct obd_export *exp, struct obd_info *oinfo,
                   obd_count page_count, struct brw_page *pga,
                   struct obd_trans_info *oti)
{
        struct obdo *saved_oa = NULL;
        struct brw_page **ppga, **orig;
        struct obd_import *imp = class_exp2cliimp(exp);
        struct client_obd *cli;
        int rc, page_count_orig;
        ENTRY;

        LASSERT((imp != NULL) && (imp->imp_obd != NULL));
        cli = &imp->imp_obd->u.cli;

        if (cmd & OBD_BRW_CHECK) {
                /* The caller just wants to know if there's a chance that this
                 * I/O can succeed */

                if (imp->imp_invalid)
                        RETURN(-EIO);
                RETURN(0);
        }

        /* test_brw with a failed create can trip this, maybe others. */
        LASSERT(cli->cl_max_pages_per_rpc);

        rc = 0;

        orig = ppga = osc_build_ppga(pga, page_count);
        if (ppga == NULL)
                RETURN(-ENOMEM);
        page_count_orig = page_count;

        sort_brw_pages(ppga, page_count);
        while (page_count) {
                obd_count pages_per_brw;

                if (page_count > cli->cl_max_pages_per_rpc)
                        pages_per_brw = cli->cl_max_pages_per_rpc;
                else
                        pages_per_brw = page_count;

                pages_per_brw = max_unfragmented_pages(ppga, pages_per_brw);

                if (saved_oa != NULL) {
                        /* restore previously saved oa */
                        *oinfo->oi_oa = *saved_oa;
                } else if (page_count > pages_per_brw) {
                        /* save a copy of oa (brw will clobber it) */
                        OBDO_ALLOC(saved_oa);
                        if (saved_oa == NULL)
                                GOTO(out, rc = -ENOMEM);
                        *saved_oa = *oinfo->oi_oa;
                }

                rc = osc_brw_internal(cmd, exp, oinfo->oi_oa, oinfo->oi_md,
                                      pages_per_brw, ppga, oinfo->oi_capa);

                if (rc != 0)
                        break;

                page_count -= pages_per_brw;
                ppga += pages_per_brw;
        }

out:
        osc_release_ppga(orig, page_count_orig);

        if (saved_oa != NULL)
                OBDO_FREE(saved_oa);

        RETURN(rc);
}

/* The companion to osc_enter_cache(), called when @oap is no longer part of
 * the dirty accounting.  Writeback completes or truncate happens before
 * writing starts.  Must be called with the loi lock held. */
static void osc_exit_cache(struct client_obd *cli, struct osc_async_page *oap,
                           int sent)
{
        osc_release_write_grant(cli, &oap->oap_brw_page, sent);
}


/* This maintains the lists of pending pages to read/write for a given object
 * (lop).  This is used by osc_check_rpcs->osc_next_loi() and loi_list_maint()
 * to quickly find objects that are ready to send an RPC. */
static int lop_makes_rpc(struct client_obd *cli, struct loi_oap_pages *lop,
                         int cmd)
{
        int optimal;
        ENTRY;

        if (lop->lop_num_pending == 0)
                RETURN(0);

        /* if we have an invalid import we want to drain the queued pages
         * by forcing them through rpcs that immediately fail and complete
         * the pages.  recovery relies on this to empty the queued pages
         * before canceling the locks and evicting down the llite pages */
        if (cli->cl_import == NULL || cli->cl_import->imp_invalid)
                RETURN(1);

        /* stream rpcs in queue order as long as as there is an urgent page
         * queued.  this is our cheap solution for good batching in the case
         * where writepage marks some random page in the middle of the file
         * as urgent because of, say, memory pressure */
        if (!cfs_list_empty(&lop->lop_urgent)) {
                CDEBUG(D_CACHE, "urgent request forcing RPC\n");
                RETURN(1);
        }
        /* fire off rpcs when we have 'optimal' rpcs as tuned for the wire. */
        optimal = cli->cl_max_pages_per_rpc;
        if (cmd & OBD_BRW_WRITE) {
                /* trigger a write rpc stream as long as there are dirtiers
                 * waiting for space.  as they're waiting, they're not going to
                 * create more pages to coalesce with what's waiting.. */
                if (!cfs_list_empty(&cli->cl_cache_waiters)) {
                        CDEBUG(D_CACHE, "cache waiters forcing RPC\n");
                        RETURN(1);
                }
                /* +16 to avoid triggering rpcs that would want to include pages
                 * that are being queued but which can't be made ready until
                 * the queuer finishes with the page. this is a wart for
                 * llite::commit_write() */
                optimal += 16;
        }
        if (lop->lop_num_pending >= optimal)
                RETURN(1);

        RETURN(0);
}

static int lop_makes_hprpc(struct loi_oap_pages *lop)
{
        struct osc_async_page *oap;
        ENTRY;

        if (cfs_list_empty(&lop->lop_urgent))
                RETURN(0);

        oap = cfs_list_entry(lop->lop_urgent.next,
                         struct osc_async_page, oap_urgent_item);

        if (oap->oap_async_flags & ASYNC_HP) {
                CDEBUG(D_CACHE, "hp request forcing RPC\n");
                RETURN(1);
        }

        RETURN(0);
}

static void on_list(cfs_list_t *item, cfs_list_t *list,
                    int should_be_on)
{
        if (cfs_list_empty(item) && should_be_on)
                cfs_list_add_tail(item, list);
        else if (!cfs_list_empty(item) && !should_be_on)
                cfs_list_del_init(item);
}

/* maintain the loi's cli list membership invariants so that osc_send_oap_rpc
 * can find pages to build into rpcs quickly */
void loi_list_maint(struct client_obd *cli, struct lov_oinfo *loi)
{
        if (lop_makes_hprpc(&loi->loi_write_lop) ||
            lop_makes_hprpc(&loi->loi_read_lop)) {
                /* HP rpc */
                on_list(&loi->loi_ready_item, &cli->cl_loi_ready_list, 0);
                on_list(&loi->loi_hp_ready_item, &cli->cl_loi_hp_ready_list, 1);
        } else {
                on_list(&loi->loi_hp_ready_item, &cli->cl_loi_hp_ready_list, 0);
                on_list(&loi->loi_ready_item, &cli->cl_loi_ready_list,
                        lop_makes_rpc(cli, &loi->loi_write_lop, OBD_BRW_WRITE)||
                        lop_makes_rpc(cli, &loi->loi_read_lop, OBD_BRW_READ));
        }

        on_list(&loi->loi_write_item, &cli->cl_loi_write_list,
                loi->loi_write_lop.lop_num_pending);

        on_list(&loi->loi_read_item, &cli->cl_loi_read_list,
                loi->loi_read_lop.lop_num_pending);
}

static void lop_update_pending(struct client_obd *cli,
                               struct loi_oap_pages *lop, int cmd, int delta)
{
        lop->lop_num_pending += delta;
        if (cmd & OBD_BRW_WRITE)
                cli->cl_pending_w_pages += delta;
        else
                cli->cl_pending_r_pages += delta;
}

/**
 * this is called when a sync waiter receives an interruption.  Its job is to
 * get the caller woken as soon as possible.  If its page hasn't been put in an
 * rpc yet it can dequeue immediately.  Otherwise it has to mark the rpc as
 * desiring interruption which will forcefully complete the rpc once the rpc
 * has timed out.
 */
int osc_oap_interrupted(const struct lu_env *env, struct osc_async_page *oap)
{
        struct loi_oap_pages *lop;
        struct lov_oinfo *loi;
        int rc = -EBUSY;
        ENTRY;

        LASSERT(!oap->oap_interrupted);
        oap->oap_interrupted = 1;

        /* ok, it's been put in an rpc. only one oap gets a request reference */
        if (oap->oap_request != NULL) {
                ptlrpc_mark_interrupted(oap->oap_request);
                ptlrpcd_wake(oap->oap_request);
                ptlrpc_req_finished(oap->oap_request);
                oap->oap_request = NULL;
        }

        /*
         * page completion may be called only if ->cpo_prep() method was
         * executed by osc_io_submit(), that also adds page the to pending list
         */
        if (!cfs_list_empty(&oap->oap_pending_item)) {
                cfs_list_del_init(&oap->oap_pending_item);
                cfs_list_del_init(&oap->oap_urgent_item);

                loi = oap->oap_loi;
                lop = (oap->oap_cmd & OBD_BRW_WRITE) ?
                        &loi->loi_write_lop : &loi->loi_read_lop;
                lop_update_pending(oap->oap_cli, lop, oap->oap_cmd, -1);
                loi_list_maint(oap->oap_cli, oap->oap_loi);
                rc = oap->oap_caller_ops->ap_completion(env,
                                          oap->oap_caller_data,
                                          oap->oap_cmd, NULL, -EINTR);
        }

        RETURN(rc);
}

/* this is trying to propogate async writeback errors back up to the
 * application.  As an async write fails we record the error code for later if
 * the app does an fsync.  As long as errors persist we force future rpcs to be
 * sync so that the app can get a sync error and break the cycle of queueing
 * pages for which writeback will fail. */
static void osc_process_ar(struct osc_async_rc *ar, __u64 xid,
                           int rc)
{
        if (rc) {
                if (!ar->ar_rc)
                        ar->ar_rc = rc;

                ar->ar_force_sync = 1;
                ar->ar_min_xid = ptlrpc_sample_next_xid();
                return;

        }

        if (ar->ar_force_sync && (xid >= ar->ar_min_xid))
                ar->ar_force_sync = 0;
}

void osc_oap_to_pending(struct osc_async_page *oap)
{
        struct loi_oap_pages *lop;

        if (oap->oap_cmd & OBD_BRW_WRITE)
                lop = &oap->oap_loi->loi_write_lop;
        else
                lop = &oap->oap_loi->loi_read_lop;

        if (oap->oap_async_flags & ASYNC_HP)
                cfs_list_add(&oap->oap_urgent_item, &lop->lop_urgent);
        else if (oap->oap_async_flags & ASYNC_URGENT)
                cfs_list_add_tail(&oap->oap_urgent_item, &lop->lop_urgent);
        cfs_list_add_tail(&oap->oap_pending_item, &lop->lop_pending);
        lop_update_pending(oap->oap_cli, lop, oap->oap_cmd, 1);
}

/* this must be called holding the loi list lock to give coverage to exit_cache,
 * async_flag maintenance, and oap_request */
static void osc_ap_completion(const struct lu_env *env,
                              struct client_obd *cli, struct obdo *oa,
                              struct osc_async_page *oap, int sent, int rc)
{
        __u64 xid = 0;

        ENTRY;
        if (oap->oap_request != NULL) {
                xid = ptlrpc_req_xid(oap->oap_request);
                ptlrpc_req_finished(oap->oap_request);
                oap->oap_request = NULL;
        }

        cfs_spin_lock(&oap->oap_lock);
        oap->oap_async_flags = 0;
        cfs_spin_unlock(&oap->oap_lock);
        oap->oap_interrupted = 0;

        if (oap->oap_cmd & OBD_BRW_WRITE) {
                osc_process_ar(&cli->cl_ar, xid, rc);
                osc_process_ar(&oap->oap_loi->loi_ar, xid, rc);
        }

        if (rc == 0 && oa != NULL) {
                if (oa->o_valid & OBD_MD_FLBLOCKS)
                        oap->oap_loi->loi_lvb.lvb_blocks = oa->o_blocks;
                if (oa->o_valid & OBD_MD_FLMTIME)
                        oap->oap_loi->loi_lvb.lvb_mtime = oa->o_mtime;
                if (oa->o_valid & OBD_MD_FLATIME)
                        oap->oap_loi->loi_lvb.lvb_atime = oa->o_atime;
                if (oa->o_valid & OBD_MD_FLCTIME)
                        oap->oap_loi->loi_lvb.lvb_ctime = oa->o_ctime;
        }

        rc = oap->oap_caller_ops->ap_completion(env, oap->oap_caller_data,
                                                oap->oap_cmd, oa, rc);

        /* ll_ap_completion (from llite) drops PG_locked. so, a new
         * I/O on the page could start, but OSC calls it under lock
         * and thus we can add oap back to pending safely */
        if (rc)
                /* upper layer wants to leave the page on pending queue */
                osc_oap_to_pending(oap);
        else
                osc_exit_cache(cli, oap, sent);
        EXIT;
}

static int brw_interpret(const struct lu_env *env,
                         struct ptlrpc_request *req, void *data, int rc)
{
        struct osc_brw_async_args *aa = data;
        struct client_obd *cli;
        int async;
        ENTRY;

        rc = osc_brw_fini_request(req, rc);
        CDEBUG(D_INODE, "request %p aa %p rc %d\n", req, aa, rc);
        if (osc_recoverable_error(rc)) {
                /* Only retry once for mmaped files since the mmaped page
                 * might be modified at anytime. We have to retry at least
                 * once in case there WAS really a corruption of the page
                 * on the network, that was not caused by mmap() modifying
                 * the page. Bug11742 */
                if ((rc == -EAGAIN) && (aa->aa_resends > 0) &&
                    aa->aa_oa->o_valid & OBD_MD_FLFLAGS &&
                    aa->aa_oa->o_flags & OBD_FL_MMAP) {
                        rc = 0;
                } else {
                        rc = osc_brw_redo_request(req, aa);
                        if (rc == 0)
                                RETURN(0);
                }
        }

        if (aa->aa_ocapa) {
                capa_put(aa->aa_ocapa);
                aa->aa_ocapa = NULL;
        }

        cli = aa->aa_cli;

        client_obd_list_lock(&cli->cl_loi_list_lock);

        /* We need to decrement before osc_ap_completion->osc_wake_cache_waiters
         * is called so we know whether to go to sync BRWs or wait for more
         * RPCs to complete */
        if (lustre_msg_get_opc(req->rq_reqmsg) == OST_WRITE)
                cli->cl_w_in_flight--;
        else
                cli->cl_r_in_flight--;

        async = cfs_list_empty(&aa->aa_oaps);
        if (!async) { /* from osc_send_oap_rpc() */
                struct osc_async_page *oap, *tmp;
                /* the caller may re-use the oap after the completion call so
                 * we need to clean it up a little */
                cfs_list_for_each_entry_safe(oap, tmp, &aa->aa_oaps,
                                             oap_rpc_item) {
                        cfs_list_del_init(&oap->oap_rpc_item);
                        osc_ap_completion(env, cli, aa->aa_oa, oap, 1, rc);
                }
                OBDO_FREE(aa->aa_oa);
        } else { /* from async_internal() */
                obd_count i;
                for (i = 0; i < aa->aa_page_count; i++)
                        osc_release_write_grant(aa->aa_cli, aa->aa_ppga[i], 1);
        }
        osc_wake_cache_waiters(cli);
        osc_check_rpcs(env, cli);
        client_obd_list_unlock(&cli->cl_loi_list_lock);
        if (!async)
                cl_req_completion(env, aa->aa_clerq, rc);
        osc_release_ppga(aa->aa_ppga, aa->aa_page_count);

        RETURN(rc);
}

static struct ptlrpc_request *osc_build_req(const struct lu_env *env,
                                            struct client_obd *cli,
                                            cfs_list_t *rpc_list,
                                            int page_count, int cmd)
{
        struct ptlrpc_request *req;
        struct brw_page **pga = NULL;
        struct osc_brw_async_args *aa;
        struct obdo *oa = NULL;
        const struct obd_async_page_ops *ops = NULL;
        void *caller_data = NULL;
        struct osc_async_page *oap;
        struct osc_async_page *tmp;
        struct ost_body *body;
        struct cl_req *clerq = NULL;
        enum cl_req_type crt = (cmd & OBD_BRW_WRITE) ? CRT_WRITE : CRT_READ;
        struct ldlm_lock *lock = NULL;
        struct cl_req_attr crattr;
        int i, rc, mpflag = 0;

        ENTRY;
        LASSERT(!cfs_list_empty(rpc_list));

        if (cmd & OBD_BRW_MEMALLOC)
                mpflag = cfs_memory_pressure_get_and_set();

        memset(&crattr, 0, sizeof crattr);
        OBD_ALLOC(pga, sizeof(*pga) * page_count);
        if (pga == NULL)
                GOTO(out, req = ERR_PTR(-ENOMEM));

        OBDO_ALLOC(oa);
        if (oa == NULL)
                GOTO(out, req = ERR_PTR(-ENOMEM));

        i = 0;
        cfs_list_for_each_entry(oap, rpc_list, oap_rpc_item) {
                struct cl_page *page = osc_oap2cl_page(oap);
                if (ops == NULL) {
                        ops = oap->oap_caller_ops;
                        caller_data = oap->oap_caller_data;

                        clerq = cl_req_alloc(env, page, crt,
                                             1 /* only 1-object rpcs for
                                                * now */);
                        if (IS_ERR(clerq))
                                GOTO(out, req = (void *)clerq);
                        lock = oap->oap_ldlm_lock;
                }
                pga[i] = &oap->oap_brw_page;
                pga[i]->off = oap->oap_obj_off + oap->oap_page_off;
                CDEBUG(0, "put page %p index %lu oap %p flg %x to pga\n",
                       pga[i]->pg, cfs_page_index(oap->oap_page), oap, pga[i]->flag);
                i++;
                cl_req_page_add(env, clerq, page);
        }

        /* always get the data for the obdo for the rpc */
        LASSERT(ops != NULL);
        crattr.cra_oa = oa;
        crattr.cra_capa = NULL;
        cl_req_attr_set(env, clerq, &crattr, ~0ULL);
        if (lock) {
                oa->o_handle = lock->l_remote_handle;
                oa->o_valid |= OBD_MD_FLHANDLE;
        }

        rc = cl_req_prep(env, clerq);
        if (rc != 0) {
                CERROR("cl_req_prep failed: %d\n", rc);
                GOTO(out, req = ERR_PTR(rc));
        }

        sort_brw_pages(pga, page_count);
        rc = osc_brw_prep_request(cmd, cli, oa, NULL, page_count,
                                  pga, &req, crattr.cra_capa, 1, 0);
        if (rc != 0) {
                CERROR("prep_req failed: %d\n", rc);
                GOTO(out, req = ERR_PTR(rc));
        }

        if (cmd & OBD_BRW_MEMALLOC)
                req->rq_memalloc = 1;

        /* Need to update the timestamps after the request is built in case
         * we race with setattr (locally or in queue at OST).  If OST gets
         * later setattr before earlier BRW (as determined by the request xid),
         * the OST will not use BRW timestamps.  Sadly, there is no obvious
         * way to do this in a single call.  bug 10150 */
        body = req_capsule_client_get(&req->rq_pill, &RMF_OST_BODY);
        cl_req_attr_set(env, clerq, &crattr,
                        OBD_MD_FLMTIME|OBD_MD_FLCTIME|OBD_MD_FLATIME);

        CLASSERT(sizeof(*aa) <= sizeof(req->rq_async_args));
        aa = ptlrpc_req_async_args(req);
        CFS_INIT_LIST_HEAD(&aa->aa_oaps);
        cfs_list_splice(rpc_list, &aa->aa_oaps);
        CFS_INIT_LIST_HEAD(rpc_list);
        aa->aa_clerq = clerq;
out:
        if (cmd & OBD_BRW_MEMALLOC)
                cfs_memory_pressure_restore(mpflag);

        capa_put(crattr.cra_capa);
        if (IS_ERR(req)) {
                if (oa)
                        OBDO_FREE(oa);
                if (pga)
                        OBD_FREE(pga, sizeof(*pga) * page_count);
                /* this should happen rarely and is pretty bad, it makes the
                 * pending list not follow the dirty order */
                client_obd_list_lock(&cli->cl_loi_list_lock);
                cfs_list_for_each_entry_safe(oap, tmp, rpc_list, oap_rpc_item) {
                        cfs_list_del_init(&oap->oap_rpc_item);

                        /* queued sync pages can be torn down while the pages
                         * were between the pending list and the rpc */
                        if (oap->oap_interrupted) {
                                CDEBUG(D_INODE, "oap %p interrupted\n", oap);
                                osc_ap_completion(env, cli, NULL, oap, 0,
                                                  oap->oap_count);
                                continue;
                        }
                        osc_ap_completion(env, cli, NULL, oap, 0, PTR_ERR(req));
                }
                if (clerq && !IS_ERR(clerq))
                        cl_req_completion(env, clerq, PTR_ERR(req));
        }
        RETURN(req);
}

/**
 * prepare pages for ASYNC io and put pages in send queue.
 *
 * \param cmd OBD_BRW_* macroses
 * \param lop pending pages
 *
 * \return zero if no page added to send queue.
 * \return 1 if pages successfully added to send queue.
 * \return negative on errors.
 */
static int
osc_send_oap_rpc(const struct lu_env *env, struct client_obd *cli,
                 struct lov_oinfo *loi,
                 int cmd, struct loi_oap_pages *lop)
{
        struct ptlrpc_request *req;
        obd_count page_count = 0;
        struct osc_async_page *oap = NULL, *tmp;
        struct osc_brw_async_args *aa;
        const struct obd_async_page_ops *ops;
        CFS_LIST_HEAD(rpc_list);
        int srvlock = 0, mem_tight = 0;
        struct cl_object *clob = NULL;
        obd_off starting_offset = OBD_OBJECT_EOF;
        unsigned int ending_offset;
        int starting_page_off = 0;
        ENTRY;

        /* ASYNC_HP pages first. At present, when the lock the pages is
         * to be canceled, the pages covered by the lock will be sent out
         * with ASYNC_HP. We have to send out them as soon as possible. */
        cfs_list_for_each_entry_safe(oap, tmp, &lop->lop_urgent, oap_urgent_item) {
                if (oap->oap_async_flags & ASYNC_HP)
                        cfs_list_move(&oap->oap_pending_item, &lop->lop_pending);
                if (++page_count >= cli->cl_max_pages_per_rpc)
                        break;
        }
        page_count = 0;

        /* first we find the pages we're allowed to work with */
        cfs_list_for_each_entry_safe(oap, tmp, &lop->lop_pending,
                                     oap_pending_item) {
                ops = oap->oap_caller_ops;

                LASSERTF(oap->oap_magic == OAP_MAGIC, "Bad oap magic: oap %p, "
                         "magic 0x%x\n", oap, oap->oap_magic);

                if (clob == NULL) {
                        /* pin object in memory, so that completion call-backs
                         * can be safely called under client_obd_list lock. */
                        clob = osc_oap2cl_page(oap)->cp_obj;
                        cl_object_get(clob);
                }

                if (page_count != 0 &&
                    srvlock != !!(oap->oap_brw_flags & OBD_BRW_SRVLOCK)) {
                        CDEBUG(D_PAGE, "SRVLOCK flag mismatch,"
                               " oap %p, page %p, srvlock %u\n",
                               oap, oap->oap_brw_page.pg, (unsigned)!srvlock);
                        break;
                }

                /* If there is a gap at the start of this page, it can't merge
                 * with any previous page, so we'll hand the network a
                 * "fragmented" page array that it can't transfer in 1 RDMA */
                if (oap->oap_obj_off < starting_offset) {
                        if (starting_page_off != 0)
                                break;

                        starting_page_off = oap->oap_page_off;
                        starting_offset = oap->oap_obj_off + starting_page_off;
                } else if (oap->oap_page_off != 0)
                        break;

                /* in llite being 'ready' equates to the page being locked
                 * until completion unlocks it.  commit_write submits a page
                 * as not ready because its unlock will happen unconditionally
                 * as the call returns.  if we race with commit_write giving
                 * us that page we don't want to create a hole in the page
                 * stream, so we stop and leave the rpc to be fired by
                 * another dirtier or kupdated interval (the not ready page
                 * will still be on the dirty list).  we could call in
                 * at the end of ll_file_write to process the queue again. */
                if (!(oap->oap_async_flags & ASYNC_READY)) {
                        int rc = ops->ap_make_ready(env, oap->oap_caller_data,
                                                    cmd);
                        if (rc < 0)
                                CDEBUG(D_INODE, "oap %p page %p returned %d "
                                                "instead of ready\n", oap,
                                                oap->oap_page, rc);
                        switch (rc) {
                        case -EAGAIN:
                                /* llite is telling us that the page is still
                                 * in commit_write and that we should try
                                 * and put it in an rpc again later.  we
                                 * break out of the loop so we don't create
                                 * a hole in the sequence of pages in the rpc
                                 * stream.*/
                                oap = NULL;
                                break;
                        case -EINTR:
                                /* the io isn't needed.. tell the checks
                                 * below to complete the rpc with EINTR */
                                cfs_spin_lock(&oap->oap_lock);
                                oap->oap_async_flags |= ASYNC_COUNT_STABLE;
                                cfs_spin_unlock(&oap->oap_lock);
                                oap->oap_count = -EINTR;
                                break;
                        case 0:
                                cfs_spin_lock(&oap->oap_lock);
                                oap->oap_async_flags |= ASYNC_READY;
                                cfs_spin_unlock(&oap->oap_lock);
                                break;
                        default:
                                LASSERTF(0, "oap %p page %p returned %d "
                                            "from make_ready\n", oap,
                                            oap->oap_page, rc);
                                break;
                        }
                }
                if (oap == NULL)
                        break;
                /*
                 * Page submitted for IO has to be locked. Either by
                 * ->ap_make_ready() or by higher layers.
                 */
#if defined(__KERNEL__) && defined(__linux__)
                {
                        struct cl_page *page;

                        page = osc_oap2cl_page(oap);

                        if (page->cp_type == CPT_CACHEABLE &&
                            !(PageLocked(oap->oap_page) &&
                              (CheckWriteback(oap->oap_page, cmd)))) {
                                CDEBUG(D_PAGE, "page %p lost wb %lx/%x\n",
                                       oap->oap_page,
                                       (long)oap->oap_page->flags,
                                       oap->oap_async_flags);
                                LBUG();
                        }
                }
#endif

                /* take the page out of our book-keeping */
                cfs_list_del_init(&oap->oap_pending_item);
                lop_update_pending(cli, lop, cmd, -1);
                cfs_list_del_init(&oap->oap_urgent_item);

                /* ask the caller for the size of the io as the rpc leaves. */
                if (!(oap->oap_async_flags & ASYNC_COUNT_STABLE)) {
                        oap->oap_count =
                                ops->ap_refresh_count(env, oap->oap_caller_data,
                                                      cmd);
                        LASSERT(oap->oap_page_off + oap->oap_count <= CFS_PAGE_SIZE);
                }
                if (oap->oap_count <= 0) {
                        CDEBUG(D_CACHE, "oap %p count %d, completing\n", oap,
                               oap->oap_count);
                        osc_ap_completion(env, cli, NULL,
                                          oap, 0, oap->oap_count);
                        continue;
                }

                /* now put the page back in our accounting */
                cfs_list_add_tail(&oap->oap_rpc_item, &rpc_list);
                if (page_count++ == 0)
                        srvlock = !!(oap->oap_brw_flags & OBD_BRW_SRVLOCK);

                if (oap->oap_brw_flags & OBD_BRW_MEMALLOC)
                        mem_tight = 1;

                /* End on a PTLRPC_MAX_BRW_SIZE boundary.  We want full-sized
                 * RPCs aligned on PTLRPC_MAX_BRW_SIZE boundaries to help reads
                 * have the same alignment as the initial writes that allocated
                 * extents on the server. */
                ending_offset = oap->oap_obj_off + oap->oap_page_off +
                                oap->oap_count;
                if (!(ending_offset & (PTLRPC_MAX_BRW_SIZE - 1)))
                        break;

                if (page_count >= cli->cl_max_pages_per_rpc)
                        break;

                /* If there is a gap at the end of this page, it can't merge
                 * with any subsequent pages, so we'll hand the network a
                 * "fragmented" page array that it can't transfer in 1 RDMA */
                if (oap->oap_page_off + oap->oap_count < CFS_PAGE_SIZE)
                        break;
        }

        osc_wake_cache_waiters(cli);

        loi_list_maint(cli, loi);

        client_obd_list_unlock(&cli->cl_loi_list_lock);

        if (clob != NULL)
                cl_object_put(env, clob);

        if (page_count == 0) {
                client_obd_list_lock(&cli->cl_loi_list_lock);
                RETURN(0);
        }

        req = osc_build_req(env, cli, &rpc_list, page_count,
                            mem_tight ? (cmd | OBD_BRW_MEMALLOC) : cmd);
        if (IS_ERR(req)) {
                LASSERT(cfs_list_empty(&rpc_list));
                loi_list_maint(cli, loi);
                RETURN(PTR_ERR(req));
        }

        aa = ptlrpc_req_async_args(req);

        starting_offset &= PTLRPC_MAX_BRW_SIZE - 1;
        if (cmd == OBD_BRW_READ) {
                lprocfs_oh_tally_log2(&cli->cl_read_page_hist, page_count);
                lprocfs_oh_tally(&cli->cl_read_rpc_hist, cli->cl_r_in_flight);
                lprocfs_oh_tally_log2(&cli->cl_read_offset_hist,
                                      (starting_offset >> CFS_PAGE_SHIFT) + 1);
        } else {
                lprocfs_oh_tally_log2(&cli->cl_write_page_hist, page_count);
                lprocfs_oh_tally(&cli->cl_write_rpc_hist,
                                 cli->cl_w_in_flight);
                lprocfs_oh_tally_log2(&cli->cl_write_offset_hist,
                                      (starting_offset >> CFS_PAGE_SHIFT) + 1);
        }
        ptlrpc_lprocfs_brw(req, aa->aa_requested_nob);

        client_obd_list_lock(&cli->cl_loi_list_lock);

        if (cmd == OBD_BRW_READ)
                cli->cl_r_in_flight++;
        else
                cli->cl_w_in_flight++;

        /* queued sync pages can be torn down while the pages
         * were between the pending list and the rpc */
        tmp = NULL;
        cfs_list_for_each_entry(oap, &aa->aa_oaps, oap_rpc_item) {
                /* only one oap gets a request reference */
                if (tmp == NULL)
                        tmp = oap;
                if (oap->oap_interrupted && !req->rq_intr) {
                        CDEBUG(D_INODE, "oap %p in req %p interrupted\n",
                               oap, req);
                        ptlrpc_mark_interrupted(req);
                }
        }
        if (tmp != NULL)
                tmp->oap_request = ptlrpc_request_addref(req);

        DEBUG_REQ(D_INODE, req, "%d pages, aa %p. now %dr/%dw in flight",
                  page_count, aa, cli->cl_r_in_flight, cli->cl_w_in_flight);

        req->rq_interpret_reply = brw_interpret;
        ptlrpcd_add_req(req, PSCOPE_BRW);
        RETURN(1);
}

#define LOI_DEBUG(LOI, STR, args...)                                     \
        CDEBUG(D_INODE, "loi ready %d wr %d:%d rd %d:%d " STR,           \
               !cfs_list_empty(&(LOI)->loi_ready_item) ||                \
               !cfs_list_empty(&(LOI)->loi_hp_ready_item),               \
               (LOI)->loi_write_lop.lop_num_pending,                     \
               !cfs_list_empty(&(LOI)->loi_write_lop.lop_urgent),        \
               (LOI)->loi_read_lop.lop_num_pending,                      \
               !cfs_list_empty(&(LOI)->loi_read_lop.lop_urgent),         \
               args)                                                     \

/* This is called by osc_check_rpcs() to find which objects have pages that
 * we could be sending.  These lists are maintained by lop_makes_rpc(). */
struct lov_oinfo *osc_next_loi(struct client_obd *cli)
{
        ENTRY;

        /* First return objects that have blocked locks so that they
         * will be flushed quickly and other clients can get the lock,
         * then objects which have pages ready to be stuffed into RPCs */
        if (!cfs_list_empty(&cli->cl_loi_hp_ready_list))
                RETURN(cfs_list_entry(cli->cl_loi_hp_ready_list.next,
                                      struct lov_oinfo, loi_hp_ready_item));
        if (!cfs_list_empty(&cli->cl_loi_ready_list))
                RETURN(cfs_list_entry(cli->cl_loi_ready_list.next,
                                      struct lov_oinfo, loi_ready_item));

        /* then if we have cache waiters, return all objects with queued
         * writes.  This is especially important when many small files
         * have filled up the cache and not been fired into rpcs because
         * they don't pass the nr_pending/object threshhold */
        if (!cfs_list_empty(&cli->cl_cache_waiters) &&
            !cfs_list_empty(&cli->cl_loi_write_list))
                RETURN(cfs_list_entry(cli->cl_loi_write_list.next,
                                      struct lov_oinfo, loi_write_item));

        /* then return all queued objects when we have an invalid import
         * so that they get flushed */
        if (cli->cl_import == NULL || cli->cl_import->imp_invalid) {
                if (!cfs_list_empty(&cli->cl_loi_write_list))
                        RETURN(cfs_list_entry(cli->cl_loi_write_list.next,
                                              struct lov_oinfo,
                                              loi_write_item));
                if (!cfs_list_empty(&cli->cl_loi_read_list))
                        RETURN(cfs_list_entry(cli->cl_loi_read_list.next,
                                              struct lov_oinfo, loi_read_item));
        }
        RETURN(NULL);
}

static int osc_max_rpc_in_flight(struct client_obd *cli, struct lov_oinfo *loi)
{
        struct osc_async_page *oap;
        int hprpc = 0;

        if (!cfs_list_empty(&loi->loi_write_lop.lop_urgent)) {
                oap = cfs_list_entry(loi->loi_write_lop.lop_urgent.next,
                                     struct osc_async_page, oap_urgent_item);
                hprpc = !!(oap->oap_async_flags & ASYNC_HP);
        }

        if (!hprpc && !cfs_list_empty(&loi->loi_read_lop.lop_urgent)) {
                oap = cfs_list_entry(loi->loi_read_lop.lop_urgent.next,
                                     struct osc_async_page, oap_urgent_item);
                hprpc = !!(oap->oap_async_flags & ASYNC_HP);
        }

        return rpcs_in_flight(cli) >= cli->cl_max_rpcs_in_flight + hprpc;
}

/* called with the loi list lock held */
void osc_check_rpcs(const struct lu_env *env, struct client_obd *cli)
{
        struct lov_oinfo *loi;
        int rc = 0, race_counter = 0;
        ENTRY;

        while ((loi = osc_next_loi(cli)) != NULL) {
                LOI_DEBUG(loi, "%lu in flight\n", rpcs_in_flight(cli));

                if (osc_max_rpc_in_flight(cli, loi))
                        break;

                /* attempt some read/write balancing by alternating between
                 * reads and writes in an object.  The makes_rpc checks here
                 * would be redundant if we were getting read/write work items
                 * instead of objects.  we don't want send_oap_rpc to drain a
                 * partial read pending queue when we're given this object to
                 * do io on writes while there are cache waiters */
                if (lop_makes_rpc(cli, &loi->loi_write_lop, OBD_BRW_WRITE)) {
                        rc = osc_send_oap_rpc(env, cli, loi, OBD_BRW_WRITE,
                                              &loi->loi_write_lop);
                        if (rc < 0) {
                                CERROR("Write request failed with %d\n", rc);

                                /* osc_send_oap_rpc failed, mostly because of
                                 * memory pressure.
                                 *
                                 * It can't break here, because if:
                                 *  - a page was submitted by osc_io_submit, so
                                 *    page locked;
                                 *  - no request in flight
                                 *  - no subsequent request
                                 * The system will be in live-lock state,
                                 * because there is no chance to call
                                 * osc_io_unplug() and osc_check_rpcs() any
                                 * more. pdflush can't help in this case,
                                 * because it might be blocked at grabbing
                                 * the page lock as we mentioned.
                                 *
                                 * Anyway, continue to drain pages. */
                                /* break; */
                        }

                        if (rc > 0)
                                race_counter = 0;
                        else if (rc == 0)
                                race_counter++;
                }
                if (lop_makes_rpc(cli, &loi->loi_read_lop, OBD_BRW_READ)) {
                        rc = osc_send_oap_rpc(env, cli, loi, OBD_BRW_READ,
                                              &loi->loi_read_lop);
                        if (rc < 0)
                                CERROR("Read request failed with %d\n", rc);

                        if (rc > 0)
                                race_counter = 0;
                        else if (rc == 0)
                                race_counter++;
                }

                /* attempt some inter-object balancing by issuing rpcs
                 * for each object in turn */
                if (!cfs_list_empty(&loi->loi_hp_ready_item))
                        cfs_list_del_init(&loi->loi_hp_ready_item);
                if (!cfs_list_empty(&loi->loi_ready_item))
                        cfs_list_del_init(&loi->loi_ready_item);
                if (!cfs_list_empty(&loi->loi_write_item))
                        cfs_list_del_init(&loi->loi_write_item);
                if (!cfs_list_empty(&loi->loi_read_item))
                        cfs_list_del_init(&loi->loi_read_item);

                loi_list_maint(cli, loi);

                /* send_oap_rpc fails with 0 when make_ready tells it to
                 * back off.  llite's make_ready does this when it tries
                 * to lock a page queued for write that is already locked.
                 * we want to try sending rpcs from many objects, but we
                 * don't want to spin failing with 0.  */
                if (race_counter == 10)
                        break;
        }
        EXIT;
}

/* we're trying to queue a page in the osc so we're subject to the
 * 'cl_dirty_max' limit on the number of pages that can be queued in the osc.
 * If the osc's queued pages are already at that limit, then we want to sleep
 * until there is space in the osc's queue for us.  We also may be waiting for
 * write credits from the OST if there are RPCs in flight that may return some
 * before we fall back to sync writes.
 *
 * We need this know our allocation was granted in the presence of signals */
static int ocw_granted(struct client_obd *cli, struct osc_cache_waiter *ocw)
{
        int rc;
        ENTRY;
        client_obd_list_lock(&cli->cl_loi_list_lock);
        rc = cfs_list_empty(&ocw->ocw_entry) || rpcs_in_flight(cli) == 0;
        client_obd_list_unlock(&cli->cl_loi_list_lock);
        RETURN(rc);
};

/**
 * Non-blocking version of osc_enter_cache() that consumes grant only when it
 * is available.
 */
int osc_enter_cache_try(const struct lu_env *env,
                        struct client_obd *cli, struct lov_oinfo *loi,
                        struct osc_async_page *oap, int transient)
{
        int has_grant;

        has_grant = cli->cl_avail_grant >= CFS_PAGE_SIZE;
        if (has_grant) {
                osc_consume_write_grant(cli, &oap->oap_brw_page);
                if (transient) {
                        cli->cl_dirty_transit += CFS_PAGE_SIZE;
                        cfs_atomic_inc(&obd_dirty_transit_pages);
                        oap->oap_brw_flags |= OBD_BRW_NOCACHE;
                }
        }
        return has_grant;
}

/* Caller must hold loi_list_lock - we drop/regain it if we need to wait for
 * grant or cache space. */
static int osc_enter_cache(const struct lu_env *env,
                           struct client_obd *cli, struct lov_oinfo *loi,
                           struct osc_async_page *oap)
{
        struct osc_cache_waiter ocw;
        struct l_wait_info lwi = LWI_INTR(LWI_ON_SIGNAL_NOOP, NULL);

        ENTRY;

        CDEBUG(D_CACHE, "dirty: %ld/%d dirty_max: %ld/%d dropped: %lu "
               "grant: %lu\n", cli->cl_dirty, cfs_atomic_read(&obd_dirty_pages),
               cli->cl_dirty_max, obd_max_dirty_pages,
               cli->cl_lost_grant, cli->cl_avail_grant);

        /* force the caller to try sync io.  this can jump the list
         * of queued writes and create a discontiguous rpc stream */
        if (OBD_FAIL_CHECK(OBD_FAIL_OSC_NO_GRANT) ||
            cli->cl_dirty_max < CFS_PAGE_SIZE     ||
            cli->cl_ar.ar_force_sync || loi->loi_ar.ar_force_sync)
                RETURN(-EDQUOT);

        /* Hopefully normal case - cache space and write credits available */
        if (cli->cl_dirty + CFS_PAGE_SIZE <= cli->cl_dirty_max &&
            cfs_atomic_read(&obd_dirty_pages) + 1 <= obd_max_dirty_pages &&
            osc_enter_cache_try(env, cli, loi, oap, 0))
                RETURN(0);

        /* It is safe to block as a cache waiter as long as there is grant
         * space available or the hope of additional grant being returned
         * when an in flight write completes.  Using the write back cache
         * if possible is preferable to sending the data synchronously
         * because write pages can then be merged in to large requests.
         * The addition of this cache waiter will causing pending write
         * pages to be sent immediately. */
        if (cli->cl_w_in_flight || cli->cl_avail_grant >= CFS_PAGE_SIZE) {
                cfs_list_add_tail(&ocw.ocw_entry, &cli->cl_cache_waiters);
                cfs_waitq_init(&ocw.ocw_waitq);
                ocw.ocw_oap = oap;
                ocw.ocw_rc = 0;

                loi_list_maint(cli, loi);
                osc_check_rpcs(env, cli);
                client_obd_list_unlock(&cli->cl_loi_list_lock);

                CDEBUG(D_CACHE, "sleeping for cache space\n");
                l_wait_event(ocw.ocw_waitq, ocw_granted(cli, &ocw), &lwi);

                client_obd_list_lock(&cli->cl_loi_list_lock);
                if (!cfs_list_empty(&ocw.ocw_entry)) {
                        cfs_list_del(&ocw.ocw_entry);
                        RETURN(-EINTR);
                }
                RETURN(ocw.ocw_rc);
        }

        RETURN(-EDQUOT);
}


int osc_prep_async_page(struct obd_export *exp, struct lov_stripe_md *lsm,
                        struct lov_oinfo *loi, cfs_page_t *page,
                        obd_off offset, const struct obd_async_page_ops *ops,
                        void *data, void **res, int nocache,
                        struct lustre_handle *lockh)
{
        struct osc_async_page *oap;

        ENTRY;

        if (!page)
                return cfs_size_round(sizeof(*oap));

        oap = *res;
        oap->oap_magic = OAP_MAGIC;
        oap->oap_cli = &exp->exp_obd->u.cli;
        oap->oap_loi = loi;

        oap->oap_caller_ops = ops;
        oap->oap_caller_data = data;

        oap->oap_page = page;
        oap->oap_obj_off = offset;
        if (!client_is_remote(exp) &&
            cfs_capable(CFS_CAP_SYS_RESOURCE))
                oap->oap_brw_flags = OBD_BRW_NOQUOTA;

        LASSERT(!(offset & ~CFS_PAGE_MASK));

        CFS_INIT_LIST_HEAD(&oap->oap_pending_item);
        CFS_INIT_LIST_HEAD(&oap->oap_urgent_item);
        CFS_INIT_LIST_HEAD(&oap->oap_rpc_item);
        CFS_INIT_LIST_HEAD(&oap->oap_page_list);

        cfs_spin_lock_init(&oap->oap_lock);
        CDEBUG(D_CACHE, "oap %p page %p obj off "LPU64"\n", oap, page, offset);
        RETURN(0);
}

int osc_queue_async_io(const struct lu_env *env, struct obd_export *exp,
                       struct lov_stripe_md *lsm, struct lov_oinfo *loi,
                       struct osc_async_page *oap, int cmd, int off,
                       int count, obd_flag brw_flags, enum async_flags async_flags)
{
        struct client_obd *cli = &exp->exp_obd->u.cli;
        int rc = 0;
        ENTRY;

        if (oap->oap_magic != OAP_MAGIC)
                RETURN(-EINVAL);

        if (cli->cl_import == NULL || cli->cl_import->imp_invalid)
                RETURN(-EIO);

        if (!cfs_list_empty(&oap->oap_pending_item) ||
            !cfs_list_empty(&oap->oap_urgent_item) ||
            !cfs_list_empty(&oap->oap_rpc_item))
                RETURN(-EBUSY);

        /* check if the file's owner/group is over quota */
        if ((cmd & OBD_BRW_WRITE) && !(cmd & OBD_BRW_NOQUOTA)) {
                struct cl_object *obj;
                struct cl_attr    attr; /* XXX put attr into thread info */
                unsigned int qid[MAXQUOTAS];

                obj = cl_object_top(osc_oap2cl_page(oap)->cp_obj);

                cl_object_attr_lock(obj);
                rc = cl_object_attr_get(env, obj, &attr);
                cl_object_attr_unlock(obj);

                qid[USRQUOTA] = attr.cat_uid;
                qid[GRPQUOTA] = attr.cat_gid;
                if (rc == 0 &&
                    lquota_chkdq(quota_interface, cli, qid) == NO_QUOTA)
                        rc = -EDQUOT;
                if (rc)
                        RETURN(rc);
        }

        if (loi == NULL)
                loi = lsm->lsm_oinfo[0];

        client_obd_list_lock(&cli->cl_loi_list_lock);

        LASSERT(off + count <= CFS_PAGE_SIZE);
        oap->oap_cmd = cmd;
        oap->oap_page_off = off;
        oap->oap_count = count;
        oap->oap_brw_flags = brw_flags;
        /* Give a hint to OST that requests are coming from kswapd - bug19529 */
        if (cfs_memory_pressure_get())
                oap->oap_brw_flags |= OBD_BRW_MEMALLOC;
        cfs_spin_lock(&oap->oap_lock);
        oap->oap_async_flags = async_flags;
        cfs_spin_unlock(&oap->oap_lock);

        if (cmd & OBD_BRW_WRITE) {
                rc = osc_enter_cache(env, cli, loi, oap);
                if (rc) {
                        client_obd_list_unlock(&cli->cl_loi_list_lock);
                        RETURN(rc);
                }
        }

        osc_oap_to_pending(oap);
        loi_list_maint(cli, loi);

        LOI_DEBUG(loi, "oap %p page %p added for cmd %d\n", oap, oap->oap_page,
                  cmd);

        osc_check_rpcs(env, cli);
        client_obd_list_unlock(&cli->cl_loi_list_lock);

        RETURN(0);
}

/* aka (~was & now & flag), but this is more clear :) */
#define SETTING(was, now, flag) (!(was & flag) && (now & flag))

int osc_set_async_flags_base(struct client_obd *cli,
                             struct lov_oinfo *loi, struct osc_async_page *oap,
                             obd_flag async_flags)
{
        struct loi_oap_pages *lop;
        int flags = 0;
        ENTRY;

        LASSERT(!cfs_list_empty(&oap->oap_pending_item));

        if (oap->oap_cmd & OBD_BRW_WRITE) {
                lop = &loi->loi_write_lop;
        } else {
                lop = &loi->loi_read_lop;
        }

        if ((oap->oap_async_flags & async_flags) == async_flags)
                RETURN(0);

        if (SETTING(oap->oap_async_flags, async_flags, ASYNC_READY))
                flags |= ASYNC_READY;

        if (SETTING(oap->oap_async_flags, async_flags, ASYNC_URGENT) &&
            cfs_list_empty(&oap->oap_rpc_item)) {
                if (oap->oap_async_flags & ASYNC_HP)
                        cfs_list_add(&oap->oap_urgent_item, &lop->lop_urgent);
                else
                        cfs_list_add_tail(&oap->oap_urgent_item,
                                          &lop->lop_urgent);
                flags |= ASYNC_URGENT;
                loi_list_maint(cli, loi);
        }
        cfs_spin_lock(&oap->oap_lock);
        oap->oap_async_flags |= flags;
        cfs_spin_unlock(&oap->oap_lock);

        LOI_DEBUG(loi, "oap %p page %p has flags %x\n", oap, oap->oap_page,
                        oap->oap_async_flags);
        RETURN(0);
}

int osc_teardown_async_page(struct obd_export *exp, struct lov_stripe_md *lsm,
                            struct lov_oinfo *loi, struct osc_async_page *oap)
{
        struct client_obd *cli = &exp->exp_obd->u.cli;
        struct loi_oap_pages *lop;
        int rc = 0;
        ENTRY;

        if (oap->oap_magic != OAP_MAGIC)
                RETURN(-EINVAL);

        if (loi == NULL)
                loi = lsm->lsm_oinfo[0];

        if (oap->oap_cmd & OBD_BRW_WRITE) {
                lop = &loi->loi_write_lop;
        } else {
                lop = &loi->loi_read_lop;
        }

        client_obd_list_lock(&cli->cl_loi_list_lock);

        if (!cfs_list_empty(&oap->oap_rpc_item))
                GOTO(out, rc = -EBUSY);

        osc_exit_cache(cli, oap, 0);
        osc_wake_cache_waiters(cli);

        if (!cfs_list_empty(&oap->oap_urgent_item)) {
                cfs_list_del_init(&oap->oap_urgent_item);
                cfs_spin_lock(&oap->oap_lock);
                oap->oap_async_flags &= ~(ASYNC_URGENT | ASYNC_HP);
                cfs_spin_unlock(&oap->oap_lock);
        }
        if (!cfs_list_empty(&oap->oap_pending_item)) {
                cfs_list_del_init(&oap->oap_pending_item);
                lop_update_pending(cli, lop, oap->oap_cmd, -1);
        }
        loi_list_maint(cli, loi);
        LOI_DEBUG(loi, "oap %p page %p torn down\n", oap, oap->oap_page);
out:
        client_obd_list_unlock(&cli->cl_loi_list_lock);
        RETURN(rc);
}

static int osc_set_lock_data_with_check(struct ldlm_lock *lock,
                                        struct ldlm_enqueue_info *einfo)
{
        void *data = einfo->ei_cbdata;
        int set = 0;

        LASSERT(lock != NULL);
        LASSERT(lock->l_blocking_ast == einfo->ei_cb_bl);
        LASSERT(lock->l_resource->lr_type == einfo->ei_type);
        LASSERT(lock->l_completion_ast == einfo->ei_cb_cp);
        LASSERT(lock->l_glimpse_ast == einfo->ei_cb_gl);

        lock_res_and_lock(lock);
        cfs_spin_lock(&osc_ast_guard);

        if (lock->l_ast_data == NULL)
                lock->l_ast_data = data;
        if (lock->l_ast_data == data)
                set = 1;

        cfs_spin_unlock(&osc_ast_guard);
        unlock_res_and_lock(lock);

        return set;
}

static int osc_set_data_with_check(struct lustre_handle *lockh,
                                   struct ldlm_enqueue_info *einfo)
{
        struct ldlm_lock *lock = ldlm_handle2lock(lockh);
        int set = 0;

        if (lock != NULL) {
                set = osc_set_lock_data_with_check(lock, einfo);
                LDLM_LOCK_PUT(lock);
        } else
                CERROR("lockh %p, data %p - client evicted?\n",
                       lockh, einfo->ei_cbdata);
        return set;
}

static int osc_change_cbdata(struct obd_export *exp, struct lov_stripe_md *lsm,
                             ldlm_iterator_t replace, void *data)
{
        struct ldlm_res_id res_id;
        struct obd_device *obd = class_exp2obd(exp);

        osc_build_res_name(lsm->lsm_object_id, lsm->lsm_object_seq, &res_id);
        ldlm_resource_iterate(obd->obd_namespace, &res_id, replace, data);
        return 0;
}

/* find any ldlm lock of the inode in osc
 * return 0    not find
 *        1    find one
 *      < 0    error */
static int osc_find_cbdata(struct obd_export *exp, struct lov_stripe_md *lsm,
                           ldlm_iterator_t replace, void *data)
{
        struct ldlm_res_id res_id;
        struct obd_device *obd = class_exp2obd(exp);
        int rc = 0;

        osc_build_res_name(lsm->lsm_object_id, lsm->lsm_object_seq, &res_id);
        rc = ldlm_resource_iterate(obd->obd_namespace, &res_id, replace, data);
        if (rc == LDLM_ITER_STOP)
                return(1);
        if (rc == LDLM_ITER_CONTINUE)
                return(0);
        return(rc);
}

static int osc_enqueue_fini(struct ptlrpc_request *req, struct ost_lvb *lvb,
                            obd_enqueue_update_f upcall, void *cookie,
                            int *flags, int rc)
{
        int intent = *flags & LDLM_FL_HAS_INTENT;
        ENTRY;

        if (intent) {
                /* The request was created before ldlm_cli_enqueue call. */
                if (rc == ELDLM_LOCK_ABORTED) {
                        struct ldlm_reply *rep;
                        rep = req_capsule_server_get(&req->rq_pill,
                                                     &RMF_DLM_REP);

                        LASSERT(rep != NULL);
                        if (rep->lock_policy_res1)
                                rc = rep->lock_policy_res1;
                }
        }

        if ((intent && rc == ELDLM_LOCK_ABORTED) || !rc) {
                *flags |= LDLM_FL_LVB_READY;
                CDEBUG(D_INODE,"got kms "LPU64" blocks "LPU64" mtime "LPU64"\n",
                       lvb->lvb_size, lvb->lvb_blocks, lvb->lvb_mtime);
        }

        /* Call the update callback. */
        rc = (*upcall)(cookie, rc);
        RETURN(rc);
}

static int osc_enqueue_interpret(const struct lu_env *env,
                                 struct ptlrpc_request *req,
                                 struct osc_enqueue_args *aa, int rc)
{
        struct ldlm_lock *lock;
        struct lustre_handle handle;
        __u32 mode;

        /* Make a local copy of a lock handle and a mode, because aa->oa_*
         * might be freed anytime after lock upcall has been called. */
        lustre_handle_copy(&handle, aa->oa_lockh);
        mode = aa->oa_ei->ei_mode;

        /* ldlm_cli_enqueue is holding a reference on the lock, so it must
         * be valid. */
        lock = ldlm_handle2lock(&handle);

        /* Take an additional reference so that a blocking AST that
         * ldlm_cli_enqueue_fini() might post for a failed lock, is guaranteed
         * to arrive after an upcall has been executed by
         * osc_enqueue_fini(). */
        ldlm_lock_addref(&handle, mode);

        /* Let CP AST to grant the lock first. */
        OBD_FAIL_TIMEOUT(OBD_FAIL_OSC_CP_ENQ_RACE, 1);

        /* Complete obtaining the lock procedure. */
        rc = ldlm_cli_enqueue_fini(aa->oa_exp, req, aa->oa_ei->ei_type, 1,
                                   mode, aa->oa_flags, aa->oa_lvb,
                                   sizeof(*aa->oa_lvb), &handle, rc);
        /* Complete osc stuff. */
        rc = osc_enqueue_fini(req, aa->oa_lvb,
                              aa->oa_upcall, aa->oa_cookie, aa->oa_flags, rc);

        OBD_FAIL_TIMEOUT(OBD_FAIL_OSC_CP_CANCEL_RACE, 10);

        /* Release the lock for async request. */
        if (lustre_handle_is_used(&handle) && rc == ELDLM_OK)
                /*
                 * Releases a reference taken by ldlm_cli_enqueue(), if it is
                 * not already released by
                 * ldlm_cli_enqueue_fini()->failed_lock_cleanup()
                 */
                ldlm_lock_decref(&handle, mode);

        LASSERTF(lock != NULL, "lockh %p, req %p, aa %p - client evicted?\n",
                 aa->oa_lockh, req, aa);
        ldlm_lock_decref(&handle, mode);
        LDLM_LOCK_PUT(lock);
        return rc;
}

void osc_update_enqueue(struct lustre_handle *lov_lockhp,
                        struct lov_oinfo *loi, int flags,
                        struct ost_lvb *lvb, __u32 mode, int rc)
{
        if (rc == ELDLM_OK) {
                struct ldlm_lock *lock = ldlm_handle2lock(lov_lockhp);
                __u64 tmp;

                LASSERT(lock != NULL);
                loi->loi_lvb = *lvb;
                tmp = loi->loi_lvb.lvb_size;
                /* Extend KMS up to the end of this lock and no further
                 * A lock on [x,y] means a KMS of up to y + 1 bytes! */
                if (tmp > lock->l_policy_data.l_extent.end)
                        tmp = lock->l_policy_data.l_extent.end + 1;
                if (tmp >= loi->loi_kms) {
                        LDLM_DEBUG(lock, "lock acquired, setting rss="LPU64
                                   ", kms="LPU64, loi->loi_lvb.lvb_size, tmp);
                        loi_kms_set(loi, tmp);
                } else {
                        LDLM_DEBUG(lock, "lock acquired, setting rss="
                                   LPU64"; leaving kms="LPU64", end="LPU64,
                                   loi->loi_lvb.lvb_size, loi->loi_kms,
                                   lock->l_policy_data.l_extent.end);
                }
                ldlm_lock_allow_match(lock);
                LDLM_LOCK_PUT(lock);
        } else if (rc == ELDLM_LOCK_ABORTED && (flags & LDLM_FL_HAS_INTENT)) {
                loi->loi_lvb = *lvb;
                CDEBUG(D_INODE, "glimpsed, setting rss="LPU64"; leaving"
                       " kms="LPU64"\n", loi->loi_lvb.lvb_size, loi->loi_kms);
                rc = ELDLM_OK;
        }
}
EXPORT_SYMBOL(osc_update_enqueue);

struct ptlrpc_request_set *PTLRPCD_SET = (void *)1;

/* When enqueuing asynchronously, locks are not ordered, we can obtain a lock
 * from the 2nd OSC before a lock from the 1st one. This does not deadlock with
 * other synchronous requests, however keeping some locks and trying to obtain
 * others may take a considerable amount of time in a case of ost failure; and
 * when other sync requests do not get released lock from a client, the client
 * is excluded from the cluster -- such scenarious make the life difficult, so
 * release locks just after they are obtained. */
int osc_enqueue_base(struct obd_export *exp, struct ldlm_res_id *res_id,
                     int *flags, ldlm_policy_data_t *policy,
                     struct ost_lvb *lvb, int kms_valid,
                     obd_enqueue_update_f upcall, void *cookie,
                     struct ldlm_enqueue_info *einfo,
                     struct lustre_handle *lockh,
                     struct ptlrpc_request_set *rqset, int async)
{
        struct obd_device *obd = exp->exp_obd;
        struct ptlrpc_request *req = NULL;
        int intent = *flags & LDLM_FL_HAS_INTENT;
        ldlm_mode_t mode;
        int rc;
        ENTRY;

        /* Filesystem lock extents are extended to page boundaries so that
         * dealing with the page cache is a little smoother.  */
        policy->l_extent.start -= policy->l_extent.start & ~CFS_PAGE_MASK;
        policy->l_extent.end |= ~CFS_PAGE_MASK;

        /*
         * kms is not valid when either object is completely fresh (so that no
         * locks are cached), or object was evicted. In the latter case cached
         * lock cannot be used, because it would prime inode state with
         * potentially stale LVB.
         */
        if (!kms_valid)
                goto no_match;

        /* Next, search for already existing extent locks that will cover us */
        /* If we're trying to read, we also search for an existing PW lock.  The
         * VFS and page cache already protect us locally, so lots of readers/
         * writers can share a single PW lock.
         *
         * There are problems with conversion deadlocks, so instead of
         * converting a read lock to a write lock, we'll just enqueue a new
         * one.
         *
         * At some point we should cancel the read lock instead of making them
         * send us a blocking callback, but there are problems with canceling
         * locks out from other users right now, too. */
        mode = einfo->ei_mode;
        if (einfo->ei_mode == LCK_PR)
                mode |= LCK_PW;
        mode = ldlm_lock_match(obd->obd_namespace,
                               *flags | LDLM_FL_LVB_READY, res_id,
                               einfo->ei_type, policy, mode, lockh, 0);
        if (mode) {
                struct ldlm_lock *matched = ldlm_handle2lock(lockh);

                if (osc_set_lock_data_with_check(matched, einfo)) {
                        /* addref the lock only if not async requests and PW
                         * lock is matched whereas we asked for PR. */
                        if (!rqset && einfo->ei_mode != mode)
                                ldlm_lock_addref(lockh, LCK_PR);
                        if (intent) {
                                /* I would like to be able to ASSERT here that
                                 * rss <= kms, but I can't, for reasons which
                                 * are explained in lov_enqueue() */
                        }

                        /* We already have a lock, and it's referenced */
                        (*upcall)(cookie, ELDLM_OK);

                        /* For async requests, decref the lock. */
                        if (einfo->ei_mode != mode)
                                ldlm_lock_decref(lockh, LCK_PW);
                        else if (rqset)
                                ldlm_lock_decref(lockh, einfo->ei_mode);
                        LDLM_LOCK_PUT(matched);
                        RETURN(ELDLM_OK);
                } else
                        ldlm_lock_decref(lockh, mode);
                LDLM_LOCK_PUT(matched);
        }

 no_match:
        if (intent) {
                CFS_LIST_HEAD(cancels);
                req = ptlrpc_request_alloc(class_exp2cliimp(exp),
                                           &RQF_LDLM_ENQUEUE_LVB);
                if (req == NULL)
                        RETURN(-ENOMEM);

                rc = ldlm_prep_enqueue_req(exp, req, &cancels, 0);
                if (rc) {
                        ptlrpc_request_free(req);
                        RETURN(rc);
                }

                req_capsule_set_size(&req->rq_pill, &RMF_DLM_LVB, RCL_SERVER,
                                     sizeof *lvb);
                ptlrpc_request_set_replen(req);
        }

        /* users of osc_enqueue() can pass this flag for ldlm_lock_match() */
        *flags &= ~LDLM_FL_BLOCK_GRANTED;

        rc = ldlm_cli_enqueue(exp, &req, einfo, res_id, policy, flags, lvb,
                              sizeof(*lvb), lockh, async);
        if (rqset) {
                if (!rc) {
                        struct osc_enqueue_args *aa;
                        CLASSERT (sizeof(*aa) <= sizeof(req->rq_async_args));
                        aa = ptlrpc_req_async_args(req);
                        aa->oa_ei = einfo;
                        aa->oa_exp = exp;
                        aa->oa_flags  = flags;
                        aa->oa_upcall = upcall;
                        aa->oa_cookie = cookie;
                        aa->oa_lvb    = lvb;
                        aa->oa_lockh  = lockh;

                        req->rq_interpret_reply =
                                (ptlrpc_interpterer_t)osc_enqueue_interpret;
                        if (rqset == PTLRPCD_SET)
                                ptlrpcd_add_req(req, PSCOPE_OTHER);
                        else
                                ptlrpc_set_add_req(rqset, req);
                } else if (intent) {
                        ptlrpc_req_finished(req);
                }
                RETURN(rc);
        }

        rc = osc_enqueue_fini(req, lvb, upcall, cookie, flags, rc);
        if (intent)
                ptlrpc_req_finished(req);

        RETURN(rc);
}

static int osc_enqueue(struct obd_export *exp, struct obd_info *oinfo,
                       struct ldlm_enqueue_info *einfo,
                       struct ptlrpc_request_set *rqset)
{
        struct ldlm_res_id res_id;
        int rc;
        ENTRY;

        osc_build_res_name(oinfo->oi_md->lsm_object_id,
                           oinfo->oi_md->lsm_object_seq, &res_id);

        rc = osc_enqueue_base(exp, &res_id, &oinfo->oi_flags, &oinfo->oi_policy,
                              &oinfo->oi_md->lsm_oinfo[0]->loi_lvb,
                              oinfo->oi_md->lsm_oinfo[0]->loi_kms_valid,
                              oinfo->oi_cb_up, oinfo, einfo, oinfo->oi_lockh,
                              rqset, rqset != NULL);
        RETURN(rc);
}

int osc_match_base(struct obd_export *exp, struct ldlm_res_id *res_id,
                   __u32 type, ldlm_policy_data_t *policy, __u32 mode,
                   int *flags, void *data, struct lustre_handle *lockh,
                   int unref)
{
        struct obd_device *obd = exp->exp_obd;
        int lflags = *flags;
        ldlm_mode_t rc;
        ENTRY;

        if (OBD_FAIL_CHECK(OBD_FAIL_OSC_MATCH))
                RETURN(-EIO);

        /* Filesystem lock extents are extended to page boundaries so that
         * dealing with the page cache is a little smoother */
        policy->l_extent.start -= policy->l_extent.start & ~CFS_PAGE_MASK;
        policy->l_extent.end |= ~CFS_PAGE_MASK;

        /* Next, search for already existing extent locks that will cover us */
        /* If we're trying to read, we also search for an existing PW lock.  The
         * VFS and page cache already protect us locally, so lots of readers/
         * writers can share a single PW lock. */
        rc = mode;
        if (mode == LCK_PR)
                rc |= LCK_PW;
        rc = ldlm_lock_match(obd->obd_namespace, lflags,
                             res_id, type, policy, rc, lockh, unref);
        if (rc) {
                if (data != NULL) {
                        if (!osc_set_data_with_check(lockh, data)) {
                                if (!(lflags & LDLM_FL_TEST_LOCK))
                                        ldlm_lock_decref(lockh, rc);
                                RETURN(0);
                        }
                }
                if (!(lflags & LDLM_FL_TEST_LOCK) && mode != rc) {
                        ldlm_lock_addref(lockh, LCK_PR);
                        ldlm_lock_decref(lockh, LCK_PW);
                }
                RETURN(rc);
        }
        RETURN(rc);
}

int osc_cancel_base(struct lustre_handle *lockh, __u32 mode)
{
        ENTRY;

        if (unlikely(mode == LCK_GROUP))
                ldlm_lock_decref_and_cancel(lockh, mode);
        else
                ldlm_lock_decref(lockh, mode);

        RETURN(0);
}

static int osc_cancel(struct obd_export *exp, struct lov_stripe_md *md,
                      __u32 mode, struct lustre_handle *lockh)
{
        ENTRY;
        RETURN(osc_cancel_base(lockh, mode));
}

static int osc_cancel_unused(struct obd_export *exp,
                             struct lov_stripe_md *lsm,
                             ldlm_cancel_flags_t flags,
                             void *opaque)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct ldlm_res_id res_id, *resp = NULL;

        if (lsm != NULL) {
                resp = osc_build_res_name(lsm->lsm_object_id,
                                          lsm->lsm_object_seq, &res_id);
        }

        return ldlm_cli_cancel_unused(obd->obd_namespace, resp, flags, opaque);
}

static int osc_statfs_interpret(const struct lu_env *env,
                                struct ptlrpc_request *req,
                                struct osc_async_args *aa, int rc)
{
        struct client_obd *cli = &req->rq_import->imp_obd->u.cli;
        struct obd_statfs *msfs;
        __u64 used;
        ENTRY;

        if (rc == -EBADR)
                /* The request has in fact never been sent
                 * due to issues at a higher level (LOV).
                 * Exit immediately since the caller is
                 * aware of the problem and takes care
                 * of the clean up */
                 RETURN(rc);

        if ((rc == -ENOTCONN || rc == -EAGAIN) &&
            (aa->aa_oi->oi_flags & OBD_STATFS_NODELAY))
                GOTO(out, rc = 0);

        if (rc != 0)
                GOTO(out, rc);

        msfs = req_capsule_server_get(&req->rq_pill, &RMF_OBD_STATFS);
        if (msfs == NULL) {
                GOTO(out, rc = -EPROTO);
        }

        /* Reinitialize the RDONLY and DEGRADED flags at the client
         * on each statfs, so they don't stay set permanently. */
        cfs_spin_lock(&cli->cl_oscc.oscc_lock);

        if (unlikely(msfs->os_state & OS_STATE_DEGRADED))
                cli->cl_oscc.oscc_flags |= OSCC_FLAG_DEGRADED;
        else if (unlikely(cli->cl_oscc.oscc_flags & OSCC_FLAG_DEGRADED))
                cli->cl_oscc.oscc_flags &= ~OSCC_FLAG_DEGRADED;

        if (unlikely(msfs->os_state & OS_STATE_READONLY))
                cli->cl_oscc.oscc_flags |= OSCC_FLAG_RDONLY;
        else if (unlikely(cli->cl_oscc.oscc_flags & OSCC_FLAG_RDONLY))
                cli->cl_oscc.oscc_flags &= ~OSCC_FLAG_RDONLY;

        /* Add a bit of hysteresis so this flag isn't continually flapping,
         * and ensure that new files don't get extremely fragmented due to
         * only a small amount of available space in the filesystem.
         * We want to set the NOSPC flag when there is less than ~0.1% free
         * and clear it when there is at least ~0.2% free space, so:
         *                   avail < ~0.1% max          max = avail + used
         *            1025 * avail < avail + used       used = blocks - free
         *            1024 * avail < used
         *            1024 * avail < blocks - free
         *                   avail < ((blocks - free) >> 10)
         *
         * On very large disk, say 16TB 0.1% will be 16 GB. We don't want to
         * lose that amount of space so in those cases we report no space left
         * if their is less than 1 GB left.                             */
        used = min_t(__u64,(msfs->os_blocks - msfs->os_bfree) >> 10, 1 << 30);
        if (unlikely(((cli->cl_oscc.oscc_flags & OSCC_FLAG_NOSPC) == 0) &&
                     ((msfs->os_ffree < 32) || (msfs->os_bavail < used))))
                cli->cl_oscc.oscc_flags |= OSCC_FLAG_NOSPC;
        else if (unlikely(((cli->cl_oscc.oscc_flags & OSCC_FLAG_NOSPC) != 0) &&
                (msfs->os_ffree > 64) && (msfs->os_bavail > (used << 1))))
                        cli->cl_oscc.oscc_flags &= ~OSCC_FLAG_NOSPC;

        cfs_spin_unlock(&cli->cl_oscc.oscc_lock);

        *aa->aa_oi->oi_osfs = *msfs;
out:
        rc = aa->aa_oi->oi_cb_up(aa->aa_oi, rc);
        RETURN(rc);
}

static int osc_statfs_async(struct obd_device *obd, struct obd_info *oinfo,
                            __u64 max_age, struct ptlrpc_request_set *rqset)
{
        struct ptlrpc_request *req;
        struct osc_async_args *aa;
        int                    rc;
        ENTRY;

        /* We could possibly pass max_age in the request (as an absolute
         * timestamp or a "seconds.usec ago") so the target can avoid doing
         * extra calls into the filesystem if that isn't necessary (e.g.
         * during mount that would help a bit).  Having relative timestamps
         * is not so great if request processing is slow, while absolute
         * timestamps are not ideal because they need time synchronization. */
        req = ptlrpc_request_alloc(obd->u.cli.cl_import, &RQF_OST_STATFS);
        if (req == NULL)
                RETURN(-ENOMEM);

        rc = ptlrpc_request_pack(req, LUSTRE_OST_VERSION, OST_STATFS);
        if (rc) {
                ptlrpc_request_free(req);
                RETURN(rc);
        }
        ptlrpc_request_set_replen(req);
        req->rq_request_portal = OST_CREATE_PORTAL;
        ptlrpc_at_set_req_timeout(req);

        if (oinfo->oi_flags & OBD_STATFS_NODELAY) {
                /* procfs requests not want stat in wait for avoid deadlock */
                req->rq_no_resend = 1;
                req->rq_no_delay = 1;
        }

        req->rq_interpret_reply = (ptlrpc_interpterer_t)osc_statfs_interpret;
        CLASSERT (sizeof(*aa) <= sizeof(req->rq_async_args));
        aa = ptlrpc_req_async_args(req);
        aa->aa_oi = oinfo;

        ptlrpc_set_add_req(rqset, req);
        RETURN(0);
}

static int osc_statfs(struct obd_device *obd, struct obd_statfs *osfs,
                      __u64 max_age, __u32 flags)
{
        struct obd_statfs     *msfs;
        struct ptlrpc_request *req;
        struct obd_import     *imp = NULL;
        int rc;
        ENTRY;

        /*Since the request might also come from lprocfs, so we need
         *sync this with client_disconnect_export Bug15684*/
        cfs_down_read(&obd->u.cli.cl_sem);
        if (obd->u.cli.cl_import)
                imp = class_import_get(obd->u.cli.cl_import);
        cfs_up_read(&obd->u.cli.cl_sem);
        if (!imp)
                RETURN(-ENODEV);

        /* We could possibly pass max_age in the request (as an absolute
         * timestamp or a "seconds.usec ago") so the target can avoid doing
         * extra calls into the filesystem if that isn't necessary (e.g.
         * during mount that would help a bit).  Having relative timestamps
         * is not so great if request processing is slow, while absolute
         * timestamps are not ideal because they need time synchronization. */
        req = ptlrpc_request_alloc(imp, &RQF_OST_STATFS);

        class_import_put(imp);

        if (req == NULL)
                RETURN(-ENOMEM);

        rc = ptlrpc_request_pack(req, LUSTRE_OST_VERSION, OST_STATFS);
        if (rc) {
                ptlrpc_request_free(req);
                RETURN(rc);
        }
        ptlrpc_request_set_replen(req);
        req->rq_request_portal = OST_CREATE_PORTAL;
        ptlrpc_at_set_req_timeout(req);

        if (flags & OBD_STATFS_NODELAY) {
                /* procfs requests not want stat in wait for avoid deadlock */
                req->rq_no_resend = 1;
                req->rq_no_delay = 1;
        }

        rc = ptlrpc_queue_wait(req);
        if (rc)
                GOTO(out, rc);

        msfs = req_capsule_server_get(&req->rq_pill, &RMF_OBD_STATFS);
        if (msfs == NULL) {
                GOTO(out, rc = -EPROTO);
        }

        *osfs = *msfs;

        EXIT;
 out:
        ptlrpc_req_finished(req);
        return rc;
}

/* Retrieve object striping information.
 *
 * @lmmu is a pointer to an in-core struct with lmm_ost_count indicating
 * the maximum number of OST indices which will fit in the user buffer.
 * lmm_magic must be LOV_MAGIC (we only use 1 slot here).
 */
static int osc_getstripe(struct lov_stripe_md *lsm, struct lov_user_md *lump)
{
        /* we use lov_user_md_v3 because it is larger than lov_user_md_v1 */
        struct lov_user_md_v3 lum, *lumk;
        struct lov_user_ost_data_v1 *lmm_objects;
        int rc = 0, lum_size;
        ENTRY;

        if (!lsm)
                RETURN(-ENODATA);

        /* we only need the header part from user space to get lmm_magic and
         * lmm_stripe_count, (the header part is common to v1 and v3) */
        lum_size = sizeof(struct lov_user_md_v1);
        if (cfs_copy_from_user(&lum, lump, lum_size))
                RETURN(-EFAULT);

        if ((lum.lmm_magic != LOV_USER_MAGIC_V1) &&
            (lum.lmm_magic != LOV_USER_MAGIC_V3))
                RETURN(-EINVAL);

        /* lov_user_md_vX and lov_mds_md_vX must have the same size */
        LASSERT(sizeof(struct lov_user_md_v1) == sizeof(struct lov_mds_md_v1));
        LASSERT(sizeof(struct lov_user_md_v3) == sizeof(struct lov_mds_md_v3));
        LASSERT(sizeof(lum.lmm_objects[0]) == sizeof(lumk->lmm_objects[0]));

        /* we can use lov_mds_md_size() to compute lum_size
         * because lov_user_md_vX and lov_mds_md_vX have the same size */
        if (lum.lmm_stripe_count > 0) {
                lum_size = lov_mds_md_size(lum.lmm_stripe_count, lum.lmm_magic);
                OBD_ALLOC(lumk, lum_size);
                if (!lumk)
                        RETURN(-ENOMEM);

                if (lum.lmm_magic == LOV_USER_MAGIC_V1)
                        lmm_objects = &(((struct lov_user_md_v1 *)lumk)->lmm_objects[0]);
                else
                        lmm_objects = &(lumk->lmm_objects[0]);
                lmm_objects->l_object_id = lsm->lsm_object_id;
        } else {
                lum_size = lov_mds_md_size(0, lum.lmm_magic);
                lumk = &lum;
        }

        lumk->lmm_object_id = lsm->lsm_object_id;
        lumk->lmm_object_seq = lsm->lsm_object_seq;
        lumk->lmm_stripe_count = 1;

        if (cfs_copy_to_user(lump, lumk, lum_size))
                rc = -EFAULT;

        if (lumk != &lum)
                OBD_FREE(lumk, lum_size);

        RETURN(rc);
}


static int osc_iocontrol(unsigned int cmd, struct obd_export *exp, int len,
                         void *karg, void *uarg)
{
        struct obd_device *obd = exp->exp_obd;
        struct obd_ioctl_data *data = karg;
        int err = 0;
        ENTRY;

        if (!cfs_try_module_get(THIS_MODULE)) {
                CERROR("Can't get module. Is it alive?");
                return -EINVAL;
        }
        switch (cmd) {
        case OBD_IOC_LOV_GET_CONFIG: {
                char *buf;
                struct lov_desc *desc;
                struct obd_uuid uuid;

                buf = NULL;
                len = 0;
                if (obd_ioctl_getdata(&buf, &len, (void *)uarg))
                        GOTO(out, err = -EINVAL);

                data = (struct obd_ioctl_data *)buf;

                if (sizeof(*desc) > data->ioc_inllen1) {
                        obd_ioctl_freedata(buf, len);
                        GOTO(out, err = -EINVAL);
                }

                if (data->ioc_inllen2 < sizeof(uuid)) {
                        obd_ioctl_freedata(buf, len);
                        GOTO(out, err = -EINVAL);
                }

                desc = (struct lov_desc *)data->ioc_inlbuf1;
                desc->ld_tgt_count = 1;
                desc->ld_active_tgt_count = 1;
                desc->ld_default_stripe_count = 1;
                desc->ld_default_stripe_size = 0;
                desc->ld_default_stripe_offset = 0;
                desc->ld_pattern = 0;
                memcpy(&desc->ld_uuid, &obd->obd_uuid, sizeof(uuid));

                memcpy(data->ioc_inlbuf2, &obd->obd_uuid, sizeof(uuid));

                err = cfs_copy_to_user((void *)uarg, buf, len);
                if (err)
                        err = -EFAULT;
                obd_ioctl_freedata(buf, len);
                GOTO(out, err);
        }
        case LL_IOC_LOV_SETSTRIPE:
                err = obd_alloc_memmd(exp, karg);
                if (err > 0)
                        err = 0;
                GOTO(out, err);
        case LL_IOC_LOV_GETSTRIPE:
                err = osc_getstripe(karg, uarg);
                GOTO(out, err);
        case OBD_IOC_CLIENT_RECOVER:
                err = ptlrpc_recover_import(obd->u.cli.cl_import,
                                            data->ioc_inlbuf1);
                if (err > 0)
                        err = 0;
                GOTO(out, err);
        case IOC_OSC_SET_ACTIVE:
                err = ptlrpc_set_import_active(obd->u.cli.cl_import,
                                               data->ioc_offset);
                GOTO(out, err);
        case OBD_IOC_POLL_QUOTACHECK:
                err = lquota_poll_check(quota_interface, exp,
                                        (struct if_quotacheck *)karg);
                GOTO(out, err);
        case OBD_IOC_PING_TARGET:
                err = ptlrpc_obd_ping(obd);
                GOTO(out, err);
        default:
                CDEBUG(D_INODE, "unrecognised ioctl %#x by %s\n",
                       cmd, cfs_curproc_comm());
                GOTO(out, err = -ENOTTY);
        }
out:
        cfs_module_put(THIS_MODULE);
        return err;
}

static int osc_get_info(struct obd_export *exp, obd_count keylen,
                        void *key, __u32 *vallen, void *val,
                        struct lov_stripe_md *lsm)
{
        ENTRY;
        if (!vallen || !val)
                RETURN(-EFAULT);

        if (KEY_IS(KEY_LOCK_TO_STRIPE)) {
                __u32 *stripe = val;
                *vallen = sizeof(*stripe);
                *stripe = 0;
                RETURN(0);
        } else if (KEY_IS(KEY_LAST_ID)) {
                struct ptlrpc_request *req;
                obd_id                *reply;
                char                  *tmp;
                int                    rc;

                req = ptlrpc_request_alloc(class_exp2cliimp(exp),
                                           &RQF_OST_GET_INFO_LAST_ID);
                if (req == NULL)
                        RETURN(-ENOMEM);

                req_capsule_set_size(&req->rq_pill, &RMF_SETINFO_KEY,
                                     RCL_CLIENT, keylen);
                rc = ptlrpc_request_pack(req, LUSTRE_OST_VERSION, OST_GET_INFO);
                if (rc) {
                        ptlrpc_request_free(req);
                        RETURN(rc);
                }

                tmp = req_capsule_client_get(&req->rq_pill, &RMF_SETINFO_KEY);
                memcpy(tmp, key, keylen);

                req->rq_no_delay = req->rq_no_resend = 1;
                ptlrpc_request_set_replen(req);
                rc = ptlrpc_queue_wait(req);
                if (rc)
                        GOTO(out, rc);

                reply = req_capsule_server_get(&req->rq_pill, &RMF_OBD_ID);
                if (reply == NULL)
                        GOTO(out, rc = -EPROTO);

                *((obd_id *)val) = *reply;
        out:
                ptlrpc_req_finished(req);
                RETURN(rc);
        } else if (KEY_IS(KEY_FIEMAP)) {
                struct ptlrpc_request *req;
                struct ll_user_fiemap *reply;
                char *tmp;
                int rc;

                req = ptlrpc_request_alloc(class_exp2cliimp(exp),
                                           &RQF_OST_GET_INFO_FIEMAP);
                if (req == NULL)
                        RETURN(-ENOMEM);

                req_capsule_set_size(&req->rq_pill, &RMF_FIEMAP_KEY,
                                     RCL_CLIENT, keylen);
                req_capsule_set_size(&req->rq_pill, &RMF_FIEMAP_VAL,
                                     RCL_CLIENT, *vallen);
                req_capsule_set_size(&req->rq_pill, &RMF_FIEMAP_VAL,
                                     RCL_SERVER, *vallen);

                rc = ptlrpc_request_pack(req, LUSTRE_OST_VERSION, OST_GET_INFO);
                if (rc) {
                        ptlrpc_request_free(req);
                        RETURN(rc);
                }

                tmp = req_capsule_client_get(&req->rq_pill, &RMF_FIEMAP_KEY);
                memcpy(tmp, key, keylen);
                tmp = req_capsule_client_get(&req->rq_pill, &RMF_FIEMAP_VAL);
                memcpy(tmp, val, *vallen);

                ptlrpc_request_set_replen(req);
                rc = ptlrpc_queue_wait(req);
                if (rc)
                        GOTO(out1, rc);

                reply = req_capsule_server_get(&req->rq_pill, &RMF_FIEMAP_VAL);
                if (reply == NULL)
                        GOTO(out1, rc = -EPROTO);

                memcpy(val, reply, *vallen);
        out1:
                ptlrpc_req_finished(req);

                RETURN(rc);
        }

        RETURN(-EINVAL);
}

static int osc_setinfo_mds_connect_import(struct obd_import *imp)
{
        struct llog_ctxt *ctxt;
        int rc = 0;
        ENTRY;

        ctxt = llog_get_context(imp->imp_obd, LLOG_MDS_OST_ORIG_CTXT);
        if (ctxt) {
                rc = llog_initiator_connect(ctxt);
                llog_ctxt_put(ctxt);
        } else {
                /* XXX return an error? skip setting below flags? */
        }

        cfs_spin_lock(&imp->imp_lock);
        imp->imp_server_timeout = 1;
        imp->imp_pingable = 1;
        cfs_spin_unlock(&imp->imp_lock);
        CDEBUG(D_RPCTRACE, "pinging OST %s\n", obd2cli_tgt(imp->imp_obd));

        RETURN(rc);
}

static int osc_setinfo_mds_conn_interpret(const struct lu_env *env,
                                          struct ptlrpc_request *req,
                                          void *aa, int rc)
{
        ENTRY;
        if (rc != 0)
                RETURN(rc);

        RETURN(osc_setinfo_mds_connect_import(req->rq_import));
}

static int osc_set_info_async(struct obd_export *exp, obd_count keylen,
                              void *key, obd_count vallen, void *val,
                              struct ptlrpc_request_set *set)
{
        struct ptlrpc_request *req;
        struct obd_device     *obd = exp->exp_obd;
        struct obd_import     *imp = class_exp2cliimp(exp);
        char                  *tmp;
        int                    rc;
        ENTRY;

        OBD_FAIL_TIMEOUT(OBD_FAIL_OSC_SHUTDOWN, 10);

        if (KEY_IS(KEY_NEXT_ID)) {
                obd_id new_val;
                struct osc_creator *oscc = &obd->u.cli.cl_oscc;

                if (vallen != sizeof(obd_id))
                        RETURN(-ERANGE);
                if (val == NULL)
                        RETURN(-EINVAL);

                if (vallen != sizeof(obd_id))
                        RETURN(-EINVAL);

                /* avoid race between allocate new object and set next id
                 * from ll_sync thread */
                cfs_spin_lock(&oscc->oscc_lock);
                new_val = *((obd_id*)val) + 1;
                if (new_val > oscc->oscc_next_id)
                        oscc->oscc_next_id = new_val;
                cfs_spin_unlock(&oscc->oscc_lock);
                CDEBUG(D_HA, "%s: set oscc_next_id = "LPU64"\n",
                       exp->exp_obd->obd_name,
                       obd->u.cli.cl_oscc.oscc_next_id);

                RETURN(0);
        }

        if (KEY_IS(KEY_CHECKSUM)) {
                if (vallen != sizeof(int))
                        RETURN(-EINVAL);
                exp->exp_obd->u.cli.cl_checksum = (*(int *)val) ? 1 : 0;
                RETURN(0);
        }

        if (KEY_IS(KEY_SPTLRPC_CONF)) {
                sptlrpc_conf_client_adapt(obd);
                RETURN(0);
        }

        if (KEY_IS(KEY_FLUSH_CTX)) {
                sptlrpc_import_flush_my_ctx(imp);
                RETURN(0);
        }

        if (!set && !KEY_IS(KEY_GRANT_SHRINK))
                RETURN(-EINVAL);

        /* We pass all other commands directly to OST. Since nobody calls osc
           methods directly and everybody is supposed to go through LOV, we
           assume lov checked invalid values for us.
           The only recognised values so far are evict_by_nid and mds_conn.
           Even if something bad goes through, we'd get a -EINVAL from OST
           anyway. */

        if (KEY_IS(KEY_GRANT_SHRINK))
                req = ptlrpc_request_alloc(imp, &RQF_OST_SET_GRANT_INFO);
        else
                req = ptlrpc_request_alloc(imp, &RQF_OBD_SET_INFO);

        if (req == NULL)
                RETURN(-ENOMEM);

        req_capsule_set_size(&req->rq_pill, &RMF_SETINFO_KEY,
                             RCL_CLIENT, keylen);
        req_capsule_set_size(&req->rq_pill, &RMF_SETINFO_VAL,
                             RCL_CLIENT, vallen);
        rc = ptlrpc_request_pack(req, LUSTRE_OST_VERSION, OST_SET_INFO);
        if (rc) {
                ptlrpc_request_free(req);
                RETURN(rc);
        }

        tmp = req_capsule_client_get(&req->rq_pill, &RMF_SETINFO_KEY);
        memcpy(tmp, key, keylen);
        tmp = req_capsule_client_get(&req->rq_pill, &RMF_SETINFO_VAL);
        memcpy(tmp, val, vallen);

        if (KEY_IS(KEY_MDS_CONN)) {
                struct osc_creator *oscc = &obd->u.cli.cl_oscc;

                oscc->oscc_oa.o_seq = (*(__u32 *)val);
                oscc->oscc_oa.o_valid |= OBD_MD_FLGROUP;
                LASSERT_SEQ_IS_MDT(oscc->oscc_oa.o_seq);
                req->rq_no_delay = req->rq_no_resend = 1;
                req->rq_interpret_reply = osc_setinfo_mds_conn_interpret;
        } else if (KEY_IS(KEY_GRANT_SHRINK)) {
                struct osc_grant_args *aa;
                struct obdo *oa;

                CLASSERT(sizeof(*aa) <= sizeof(req->rq_async_args));
                aa = ptlrpc_req_async_args(req);
                OBDO_ALLOC(oa);
                if (!oa) {
                        ptlrpc_req_finished(req);
                        RETURN(-ENOMEM);
                }
                *oa = ((struct ost_body *)val)->oa;
                aa->aa_oa = oa;
                req->rq_interpret_reply = osc_shrink_grant_interpret;
        }

        ptlrpc_request_set_replen(req);
        if (!KEY_IS(KEY_GRANT_SHRINK)) {
                LASSERT(set != NULL);
                ptlrpc_set_add_req(set, req);
                ptlrpc_check_set(NULL, set);
        } else
                ptlrpcd_add_req(req, PSCOPE_OTHER);

        RETURN(0);
}


static struct llog_operations osc_size_repl_logops = {
        lop_cancel: llog_obd_repl_cancel
};

static struct llog_operations osc_mds_ost_orig_logops;

static int __osc_llog_init(struct obd_device *obd, struct obd_llog_group *olg,
                           struct obd_device *tgt, struct llog_catid *catid)
{
        int rc;
        ENTRY;

        rc = llog_setup(obd, &obd->obd_olg, LLOG_MDS_OST_ORIG_CTXT, tgt, 1,
                        &catid->lci_logid, &osc_mds_ost_orig_logops);
        if (rc) {
                CERROR("failed LLOG_MDS_OST_ORIG_CTXT\n");
                GOTO(out, rc);
        }

        rc = llog_setup(obd, &obd->obd_olg, LLOG_SIZE_REPL_CTXT, tgt, 1,
                        NULL, &osc_size_repl_logops);
        if (rc) {
                struct llog_ctxt *ctxt =
                        llog_get_context(obd, LLOG_MDS_OST_ORIG_CTXT);
                if (ctxt)
                        llog_cleanup(ctxt);
                CERROR("failed LLOG_SIZE_REPL_CTXT\n");
        }
        GOTO(out, rc);
out:
        if (rc) {
                CERROR("osc '%s' tgt '%s' catid %p rc=%d\n",
                       obd->obd_name, tgt->obd_name, catid, rc);
                CERROR("logid "LPX64":0x%x\n",
                       catid->lci_logid.lgl_oid, catid->lci_logid.lgl_ogen);
        }
        return rc;
}

static int osc_llog_init(struct obd_device *obd, struct obd_llog_group *olg,
                         struct obd_device *disk_obd, int *index)
{
        struct llog_catid catid;
        static char name[32] = CATLIST;
        int rc;
        ENTRY;

        LASSERT(olg == &obd->obd_olg);

        cfs_mutex_down(&olg->olg_cat_processing);
        rc = llog_get_cat_list(disk_obd, name, *index, 1, &catid);
        if (rc) {
                CERROR("rc: %d\n", rc);
                GOTO(out, rc);
        }

        CDEBUG(D_INFO, "%s: Init llog for %d - catid "LPX64"/"LPX64":%x\n",
               obd->obd_name, *index, catid.lci_logid.lgl_oid,
               catid.lci_logid.lgl_oseq, catid.lci_logid.lgl_ogen);

        rc = __osc_llog_init(obd, olg, disk_obd, &catid);
        if (rc) {
                CERROR("rc: %d\n", rc);
                GOTO(out, rc);
        }

        rc = llog_put_cat_list(disk_obd, name, *index, 1, &catid);
        if (rc) {
                CERROR("rc: %d\n", rc);
                GOTO(out, rc);
        }

 out:
        cfs_mutex_up(&olg->olg_cat_processing);

        return rc;
}

static int osc_llog_finish(struct obd_device *obd, int count)
{
        struct llog_ctxt *ctxt;
        int rc = 0, rc2 = 0;
        ENTRY;

        ctxt = llog_get_context(obd, LLOG_MDS_OST_ORIG_CTXT);
        if (ctxt)
                rc = llog_cleanup(ctxt);

        ctxt = llog_get_context(obd, LLOG_SIZE_REPL_CTXT);
        if (ctxt)
                rc2 = llog_cleanup(ctxt);
        if (!rc)
                rc = rc2;

        RETURN(rc);
}

static int osc_reconnect(const struct lu_env *env,
                         struct obd_export *exp, struct obd_device *obd,
                         struct obd_uuid *cluuid,
                         struct obd_connect_data *data,
                         void *localdata)
{
        struct client_obd *cli = &obd->u.cli;

        if (data != NULL && (data->ocd_connect_flags & OBD_CONNECT_GRANT)) {
                long lost_grant;

                client_obd_list_lock(&cli->cl_loi_list_lock);
                data->ocd_grant = (cli->cl_avail_grant + cli->cl_dirty) ?:
                                2 * cli->cl_max_pages_per_rpc << CFS_PAGE_SHIFT;
                lost_grant = cli->cl_lost_grant;
                cli->cl_lost_grant = 0;
                client_obd_list_unlock(&cli->cl_loi_list_lock);

                CDEBUG(D_CACHE, "request ocd_grant: %d cl_avail_grant: %ld "
                       "cl_dirty: %ld cl_lost_grant: %ld\n", data->ocd_grant,
                       cli->cl_avail_grant, cli->cl_dirty, lost_grant);
                CDEBUG(D_RPCTRACE, "ocd_connect_flags: "LPX64" ocd_version: %d"
                       " ocd_grant: %d\n", data->ocd_connect_flags,
                       data->ocd_version, data->ocd_grant);
        }

        RETURN(0);
}

static int osc_disconnect(struct obd_export *exp)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct llog_ctxt  *ctxt;
        int rc;

        ctxt = llog_get_context(obd, LLOG_SIZE_REPL_CTXT);
        if (ctxt) {
                if (obd->u.cli.cl_conn_count == 1) {
                        /* Flush any remaining cancel messages out to the
                         * target */
                        llog_sync(ctxt, exp);
                }
                llog_ctxt_put(ctxt);
        } else {
                CDEBUG(D_HA, "No LLOG_SIZE_REPL_CTXT found in obd %p\n",
                       obd);
        }

        rc = client_disconnect_export(exp);
        /**
         * Initially we put del_shrink_grant before disconnect_export, but it
         * causes the following problem if setup (connect) and cleanup
         * (disconnect) are tangled together.
         *      connect p1                     disconnect p2
         *   ptlrpc_connect_import
         *     ...............               class_manual_cleanup
         *                                     osc_disconnect
         *                                     del_shrink_grant
         *   ptlrpc_connect_interrupt
         *     init_grant_shrink
         *   add this client to shrink list
         *                                      cleanup_osc
         * Bang! pinger trigger the shrink.
         * So the osc should be disconnected from the shrink list, after we
         * are sure the import has been destroyed. BUG18662
         */
        if (obd->u.cli.cl_import == NULL)
                osc_del_shrink_grant(&obd->u.cli);
        return rc;
}

static int osc_import_event(struct obd_device *obd,
                            struct obd_import *imp,
                            enum obd_import_event event)
{
        struct client_obd *cli;
        int rc = 0;

        ENTRY;
        LASSERT(imp->imp_obd == obd);

        switch (event) {
        case IMP_EVENT_DISCON: {
                /* Only do this on the MDS OSC's */
                if (imp->imp_server_timeout) {
                        struct osc_creator *oscc = &obd->u.cli.cl_oscc;

                        cfs_spin_lock(&oscc->oscc_lock);
                        oscc->oscc_flags |= OSCC_FLAG_RECOVERING;
                        cfs_spin_unlock(&oscc->oscc_lock);
                }
                cli = &obd->u.cli;
                client_obd_list_lock(&cli->cl_loi_list_lock);
                cli->cl_avail_grant = 0;
                cli->cl_lost_grant = 0;
                client_obd_list_unlock(&cli->cl_loi_list_lock);
                break;
        }
        case IMP_EVENT_INACTIVE: {
                rc = obd_notify_observer(obd, obd, OBD_NOTIFY_INACTIVE, NULL);
                break;
        }
        case IMP_EVENT_INVALIDATE: {
                struct ldlm_namespace *ns = obd->obd_namespace;
                struct lu_env         *env;
                int                    refcheck;

                env = cl_env_get(&refcheck);
                if (!IS_ERR(env)) {
                        /* Reset grants */
                        cli = &obd->u.cli;
                        client_obd_list_lock(&cli->cl_loi_list_lock);
                        /* all pages go to failing rpcs due to the invalid
                         * import */
                        osc_check_rpcs(env, cli);
                        client_obd_list_unlock(&cli->cl_loi_list_lock);

                        ldlm_namespace_cleanup(ns, LDLM_FL_LOCAL_ONLY);
                        cl_env_put(env, &refcheck);
                } else
                        rc = PTR_ERR(env);
                break;
        }
        case IMP_EVENT_ACTIVE: {
                /* Only do this on the MDS OSC's */
                if (imp->imp_server_timeout) {
                        struct osc_creator *oscc = &obd->u.cli.cl_oscc;

                        cfs_spin_lock(&oscc->oscc_lock);
                        oscc->oscc_flags &= ~OSCC_FLAG_NOSPC;
                        cfs_spin_unlock(&oscc->oscc_lock);
                }
                rc = obd_notify_observer(obd, obd, OBD_NOTIFY_ACTIVE, NULL);
                break;
        }
        case IMP_EVENT_OCD: {
                struct obd_connect_data *ocd = &imp->imp_connect_data;

                if (ocd->ocd_connect_flags & OBD_CONNECT_GRANT)
                        osc_init_grant(&obd->u.cli, ocd);

                /* See bug 7198 */
                if (ocd->ocd_connect_flags & OBD_CONNECT_REQPORTAL)
                        imp->imp_client->cli_request_portal =OST_REQUEST_PORTAL;

                rc = obd_notify_observer(obd, obd, OBD_NOTIFY_OCD, NULL);
                break;
        }
        case IMP_EVENT_DEACTIVATE: {
                rc = obd_notify_observer(obd, obd, OBD_NOTIFY_DEACTIVATE, NULL);
                break;
        }
        case IMP_EVENT_ACTIVATE: {
                rc = obd_notify_observer(obd, obd, OBD_NOTIFY_ACTIVATE, NULL);
                break;
        }
        default:
                CERROR("Unknown import event %d\n", event);
                LBUG();
        }
        RETURN(rc);
}

/**
 * Determine whether the lock can be canceled before replaying the lock
 * during recovery, see bug16774 for detailed information.
 *
 * \retval zero the lock can't be canceled
 * \retval other ok to cancel
 */
static int osc_cancel_for_recovery(struct ldlm_lock *lock)
{
        check_res_locked(lock->l_resource);

        /*
         * Cancel all unused extent lock in granted mode LCK_PR or LCK_CR.
         *
         * XXX as a future improvement, we can also cancel unused write lock
         * if it doesn't have dirty data and active mmaps.
         */
        if (lock->l_resource->lr_type == LDLM_EXTENT &&
            (lock->l_granted_mode == LCK_PR ||
             lock->l_granted_mode == LCK_CR) &&
            (osc_dlm_lock_pageref(lock) == 0))
                RETURN(1);

        RETURN(0);
}

int osc_setup(struct obd_device *obd, struct lustre_cfg *lcfg)
{
        int rc;
        ENTRY;

        ENTRY;
        rc = ptlrpcd_addref();
        if (rc)
                RETURN(rc);

        rc = client_obd_setup(obd, lcfg);
        if (rc) {
                ptlrpcd_decref();
        } else {
                struct lprocfs_static_vars lvars = { 0 };
                struct client_obd *cli = &obd->u.cli;

                cli->cl_grant_shrink_interval = GRANT_SHRINK_INTERVAL;
                lprocfs_osc_init_vars(&lvars);
                if (lprocfs_obd_setup(obd, lvars.obd_vars) == 0) {
                        lproc_osc_attach_seqstat(obd);
                        sptlrpc_lprocfs_cliobd_attach(obd);
                        ptlrpc_lprocfs_register_obd(obd);
                }

                oscc_init(obd);
                /* We need to allocate a few requests more, because
                   brw_interpret tries to create new requests before freeing
                   previous ones. Ideally we want to have 2x max_rpcs_in_flight
                   reserved, but I afraid that might be too much wasted RAM
                   in fact, so 2 is just my guess and still should work. */
                cli->cl_import->imp_rq_pool =
                        ptlrpc_init_rq_pool(cli->cl_max_rpcs_in_flight + 2,
                                            OST_MAXREQSIZE,
                                            ptlrpc_add_rqs_to_pool);

                CFS_INIT_LIST_HEAD(&cli->cl_grant_shrink_list);
                cfs_sema_init(&cli->cl_grant_sem, 1);

                ns_register_cancel(obd->obd_namespace, osc_cancel_for_recovery);
        }

        RETURN(rc);
}

static int osc_precleanup(struct obd_device *obd, enum obd_cleanup_stage stage)
{
        int rc = 0;
        ENTRY;

        switch (stage) {
        case OBD_CLEANUP_EARLY: {
                struct obd_import *imp;
                imp = obd->u.cli.cl_import;
                CDEBUG(D_HA, "Deactivating import %s\n", obd->obd_name);
                /* ptlrpc_abort_inflight to stop an mds_lov_synchronize */
                ptlrpc_deactivate_import(imp);
                cfs_spin_lock(&imp->imp_lock);
                imp->imp_pingable = 0;
                cfs_spin_unlock(&imp->imp_lock);
                break;
        }
        case OBD_CLEANUP_EXPORTS: {
                /* LU-464
                 * for echo client, export may be on zombie list, wait for
                 * zombie thread to cull it, because cli.cl_import will be
                 * cleared in client_disconnect_export():
                 *   class_export_destroy() -> obd_cleanup() ->
                 *   echo_device_free() -> echo_client_cleanup() ->
                 *   obd_disconnect() -> osc_disconnect() ->
                 *   client_disconnect_export()
                 */
                obd_zombie_barrier();
                /* If we set up but never connected, the
                   client import will not have been cleaned. */
                if (obd->u.cli.cl_import) {
                        struct obd_import *imp;
                        cfs_down_write(&obd->u.cli.cl_sem);
                        imp = obd->u.cli.cl_import;
                        CDEBUG(D_CONFIG, "%s: client import never connected\n",
                               obd->obd_name);
                        ptlrpc_invalidate_import(imp);
                        if (imp->imp_rq_pool) {
                                ptlrpc_free_rq_pool(imp->imp_rq_pool);
                                imp->imp_rq_pool = NULL;
                        }
                        class_destroy_import(imp);
                        cfs_up_write(&obd->u.cli.cl_sem);
                        obd->u.cli.cl_import = NULL;
                }
                rc = obd_llog_finish(obd, 0);
                if (rc != 0)
                        CERROR("failed to cleanup llogging subsystems\n");
                break;
                }
        }
        RETURN(rc);
}

int osc_cleanup(struct obd_device *obd)
{
        int rc;

        ENTRY;
        ptlrpc_lprocfs_unregister_obd(obd);
        lprocfs_obd_cleanup(obd);

        /* free memory of osc quota cache */
        lquota_cleanup(quota_interface, obd);

        rc = client_obd_cleanup(obd);

        ptlrpcd_decref();
        RETURN(rc);
}

int osc_process_config_base(struct obd_device *obd, struct lustre_cfg *lcfg)
{
        struct lprocfs_static_vars lvars = { 0 };
        int rc = 0;

        lprocfs_osc_init_vars(&lvars);

        switch (lcfg->lcfg_command) {
        default:
                rc = class_process_proc_param(PARAM_OSC, lvars.obd_vars,
                                              lcfg, obd);
                if (rc > 0)
                        rc = 0;
                break;
        }

        return(rc);
}

static int osc_process_config(struct obd_device *obd, obd_count len, void *buf)
{
        return osc_process_config_base(obd, buf);
}

struct obd_ops osc_obd_ops = {
        .o_owner                = THIS_MODULE,
        .o_setup                = osc_setup,
        .o_precleanup           = osc_precleanup,
        .o_cleanup              = osc_cleanup,
        .o_add_conn             = client_import_add_conn,
        .o_del_conn             = client_import_del_conn,
        .o_connect              = client_connect_import,
        .o_reconnect            = osc_reconnect,
        .o_disconnect           = osc_disconnect,
        .o_statfs               = osc_statfs,
        .o_statfs_async         = osc_statfs_async,
        .o_packmd               = osc_packmd,
        .o_unpackmd             = osc_unpackmd,
        .o_precreate            = osc_precreate,
        .o_create               = osc_create,
        .o_create_async         = osc_create_async,
        .o_destroy              = osc_destroy,
        .o_getattr              = osc_getattr,
        .o_getattr_async        = osc_getattr_async,
        .o_setattr              = osc_setattr,
        .o_setattr_async        = osc_setattr_async,
        .o_brw                  = osc_brw,
        .o_punch                = osc_punch,
        .o_sync                 = osc_sync,
        .o_enqueue              = osc_enqueue,
        .o_change_cbdata        = osc_change_cbdata,
        .o_find_cbdata          = osc_find_cbdata,
        .o_cancel               = osc_cancel,
        .o_cancel_unused        = osc_cancel_unused,
        .o_iocontrol            = osc_iocontrol,
        .o_get_info             = osc_get_info,
        .o_set_info_async       = osc_set_info_async,
        .o_import_event         = osc_import_event,
        .o_llog_init            = osc_llog_init,
        .o_llog_finish          = osc_llog_finish,
        .o_process_config       = osc_process_config,
};

extern struct lu_kmem_descr osc_caches[];
extern cfs_spinlock_t       osc_ast_guard;
extern cfs_lock_class_key_t osc_ast_guard_class;

int __init osc_init(void)
{
        struct lprocfs_static_vars lvars = { 0 };
        int rc;
        ENTRY;

        /* print an address of _any_ initialized kernel symbol from this
         * module, to allow debugging with gdb that doesn't support data
         * symbols from modules.*/
        CDEBUG(D_CONSOLE, "Lustre OSC module (%p).\n", &osc_caches);

        rc = lu_kmem_init(osc_caches);

        lprocfs_osc_init_vars(&lvars);

        cfs_request_module("lquota");
        quota_interface = PORTAL_SYMBOL_GET(osc_quota_interface);
        lquota_init(quota_interface);
        init_obd_quota_ops(quota_interface, &osc_obd_ops);

        rc = class_register_type(&osc_obd_ops, NULL, lvars.module_vars,
                                 LUSTRE_OSC_NAME, &osc_device_type);
        if (rc) {
                if (quota_interface)
                        PORTAL_SYMBOL_PUT(osc_quota_interface);
                lu_kmem_fini(osc_caches);
                RETURN(rc);
        }

        cfs_spin_lock_init(&osc_ast_guard);
        cfs_lockdep_set_class(&osc_ast_guard, &osc_ast_guard_class);

        osc_mds_ost_orig_logops = llog_lvfs_ops;
        osc_mds_ost_orig_logops.lop_setup = llog_obd_origin_setup;
        osc_mds_ost_orig_logops.lop_cleanup = llog_obd_origin_cleanup;
        osc_mds_ost_orig_logops.lop_add = llog_obd_origin_add;
        osc_mds_ost_orig_logops.lop_connect = llog_origin_connect;

        RETURN(rc);
}

#ifdef __KERNEL__
static void /*__exit*/ osc_exit(void)
{
        lu_device_type_fini(&osc_device_type);

        lquota_exit(quota_interface);
        if (quota_interface)
                PORTAL_SYMBOL_PUT(osc_quota_interface);

        class_unregister_type(LUSTRE_OSC_NAME);
        lu_kmem_fini(osc_caches);
}

MODULE_AUTHOR("Sun Microsystems, Inc. <http://www.lustre.org/>");
MODULE_DESCRIPTION("Lustre Object Storage Client (OSC)");
MODULE_LICENSE("GPL");

cfs_module(osc, LUSTRE_VERSION_STRING, osc_init, osc_exit);
#endif
