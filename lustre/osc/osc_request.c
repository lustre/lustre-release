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
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_OSC

#ifdef __KERNEL__
# include <libcfs/libcfs.h>
#else /* __KERNEL__ */
# include <liblustre.h>
#endif

# include <lustre_dlm.h>
#include <libcfs/kp30.h>
#include <lustre_net.h>
#include <lustre/lustre_user.h>
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
#include <lustre_cache.h>
#include "osc_internal.h"

static quota_interface_t *quota_interface = NULL;
extern quota_interface_t osc_quota_interface;

static void osc_release_ppga(struct brw_page **ppga, obd_count count);
static int brw_interpret(struct ptlrpc_request *request, void *data, int rc);
int osc_cleanup(struct obd_device *obd);

static quota_interface_t *quota_interface;
extern quota_interface_t osc_quota_interface;

/* by default 10s */
atomic_t osc_resend_time;

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
                (*lmmp)->lmm_object_id = cpu_to_le64(lsm->lsm_object_id);
        }

        RETURN(lmm_size);
}

/* Unpack OSC object metadata from disk storage (LE byte order). */
static int osc_unpackmd(struct obd_export *exp, struct lov_stripe_md **lsmp,
                        struct lov_mds_md *lmm, int lmm_bytes)
{
        int lsm_size;
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
                LASSERT((*lsmp)->lsm_object_id);
        }

        (*lsmp)->lsm_maxbytes = LUSTRE_STRIPE_MAXBYTES;

        RETURN(lsm_size);
}

static int osc_getattr_interpret(struct ptlrpc_request *req,
                                 void *data, int rc)
{
        struct ost_body *body;
        struct osc_async_args *aa = data;
        ENTRY;

        if (rc != 0)
                GOTO(out, rc);

        body = lustre_swab_repbuf(req, REPLY_REC_OFF, sizeof(*body),
                                  lustre_swab_ost_body);
        if (body) {
                CDEBUG(D_INODE, "mode: %o\n", body->oa.o_mode);
                lustre_get_wire_obdo(aa->aa_oi->oi_oa, &body->oa);

                /* This should really be sent by the OST */
                aa->aa_oi->oi_oa->o_blksize = PTLRPC_MAX_BRW_SIZE;
                aa->aa_oi->oi_oa->o_valid |= OBD_MD_FLBLKSZ;
        } else {
                CERROR("can't unpack ost_body\n");
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
        struct ost_body *body;
        __u32 size[2] = { sizeof(struct ptlrpc_body), sizeof(*body) };
        struct osc_async_args *aa;
        ENTRY;

        req = ptlrpc_prep_req(class_exp2cliimp(exp), LUSTRE_OST_VERSION,
                              OST_GETATTR, 2, size,NULL);
        if (!req)
                RETURN(-ENOMEM);

        body = lustre_msg_buf(req->rq_reqmsg, REQ_REC_OFF, sizeof(*body));
        lustre_set_wire_obdo(&body->oa, oinfo->oi_oa);

        ptlrpc_req_set_repsize(req, 2, size);
        req->rq_interpret_reply = osc_getattr_interpret;

        CLASSERT(sizeof(*aa) <= sizeof(req->rq_async_args));
        aa = ptlrpc_req_async_args(req);
        aa->aa_oi = oinfo;

        ptlrpc_set_add_req(set, req);
        RETURN (0);
}

static int osc_getattr(struct obd_export *exp, struct obd_info *oinfo)
{
        struct ptlrpc_request *req;
        struct ost_body *body;
        __u32 size[2] = { sizeof(struct ptlrpc_body), sizeof(*body) };
        int rc;
        ENTRY;

        req = ptlrpc_prep_req(class_exp2cliimp(exp), LUSTRE_OST_VERSION,
                              OST_GETATTR, 2, size, NULL);
        if (!req)
                RETURN(-ENOMEM);

        body = lustre_msg_buf(req->rq_reqmsg, REQ_REC_OFF, sizeof(*body));
        lustre_set_wire_obdo(&body->oa, oinfo->oi_oa);

        ptlrpc_req_set_repsize(req, 2, size);

        rc = ptlrpc_queue_wait(req);
        if (rc) {
                CERROR("%s failed: rc = %d\n", __FUNCTION__, rc);
                GOTO(out, rc);
        }

        body = lustre_swab_repbuf(req, REPLY_REC_OFF, sizeof(*body),
                                  lustre_swab_ost_body);
        if (body == NULL) {
                CERROR ("can't unpack ost_body\n");
                GOTO (out, rc = -EPROTO);
        }

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
        struct ost_body *body;
        __u32 size[2] = { sizeof(struct ptlrpc_body), sizeof(*body) };
        int rc;
        ENTRY;

        req = ptlrpc_prep_req(class_exp2cliimp(exp), LUSTRE_OST_VERSION,
                              OST_SETATTR, 2, size, NULL);
        if (!req)
                RETURN(-ENOMEM);

        body = lustre_msg_buf(req->rq_reqmsg, REQ_REC_OFF, sizeof(*body));
        lustre_set_wire_obdo(&body->oa, oinfo->oi_oa);

        ptlrpc_req_set_repsize(req, 2, size);

        rc = ptlrpc_queue_wait(req);
        if (rc)
                GOTO(out, rc);

        body = lustre_swab_repbuf(req, REPLY_REC_OFF, sizeof(*body),
                                  lustre_swab_ost_body);
        if (body == NULL)
                GOTO(out, rc = -EPROTO);

        lustre_get_wire_obdo(oinfo->oi_oa, &body->oa);

        EXIT;
out:
        ptlrpc_req_finished(req);
        RETURN(rc);
}

static int osc_setattr_interpret(struct ptlrpc_request *req,
                                 void *data, int rc)
{
        struct ost_body *body;
        struct osc_async_args *aa = data;
        ENTRY;

        if (rc != 0)
                GOTO(out, rc);

        body = lustre_swab_repbuf(req, REPLY_REC_OFF, sizeof(*body),
                                  lustre_swab_ost_body);
        if (body == NULL) {
                CERROR("can't unpack ost_body\n");
                GOTO(out, rc = -EPROTO);
        }

        lustre_get_wire_obdo(aa->aa_oi->oi_oa, &body->oa);
out:
        rc = aa->aa_oi->oi_cb_up(aa->aa_oi, rc);
        RETURN(rc);
}

static int osc_setattr_async(struct obd_export *exp, struct obd_info *oinfo,
                             struct obd_trans_info *oti,
                             struct ptlrpc_request_set *rqset)
{
        struct ptlrpc_request *req;
        struct ost_body *body;
        __u32 size[3] = { sizeof(struct ptlrpc_body), sizeof(*body), 0 };
        int bufcount = 2;
        struct osc_async_args *aa;
        ENTRY;

        if (osc_exp_is_2_0_server(exp)) {
                bufcount = 3;
        }

        req = ptlrpc_prep_req(class_exp2cliimp(exp), LUSTRE_OST_VERSION,
                              OST_SETATTR, bufcount, size, NULL);
        if (!req)
                RETURN(-ENOMEM);

        body = lustre_msg_buf(req->rq_reqmsg, REQ_REC_OFF, sizeof(*body));

        if (oinfo->oi_oa->o_valid & OBD_MD_FLCOOKIE) {
                LASSERT(oti);
                oinfo->oi_oa->o_lcookie = *oti->oti_logcookies;
        }

        lustre_set_wire_obdo(&body->oa, oinfo->oi_oa);
        ptlrpc_req_set_repsize(req, 2, size);
        /* do mds to ost setattr asynchronouly */
        if (!rqset) {
                /* Do not wait for response. */
                ptlrpcd_add_req(req);
        } else {
                req->rq_interpret_reply = osc_setattr_interpret;

                CLASSERT(sizeof(*aa) <= sizeof(req->rq_async_args));
                aa = ptlrpc_req_async_args(req);
                aa->aa_oi = oinfo;

                ptlrpc_set_add_req(rqset, req);
        }

        RETURN(0);
}

int osc_real_create(struct obd_export *exp, struct obdo *oa,
                    struct lov_stripe_md **ea, struct obd_trans_info *oti)
{
        struct ptlrpc_request *req;
        struct ost_body *body;
        struct lov_stripe_md *lsm;
        __u32 size[2] = { sizeof(struct ptlrpc_body), sizeof(*body) };
        int rc;
        ENTRY;

        LASSERT(oa);
        LASSERT(ea);

        lsm = *ea;
        if (!lsm) {
                rc = obd_alloc_memmd(exp, &lsm);
                if (rc < 0)
                        RETURN(rc);
        }

        req = ptlrpc_prep_req(class_exp2cliimp(exp), LUSTRE_OST_VERSION,
                              OST_CREATE, 2, size, NULL);
        if (!req)
                GOTO(out, rc = -ENOMEM);

        body = lustre_msg_buf(req->rq_reqmsg, REQ_REC_OFF, sizeof(*body));
        lustre_set_wire_obdo(&body->oa, oa);

        ptlrpc_req_set_repsize(req, 2, size);
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

        body = lustre_swab_repbuf(req, REPLY_REC_OFF, sizeof(*body),
                                  lustre_swab_ost_body);
        if (body == NULL) {
                CERROR ("can't unpack ost_body\n");
                GOTO (out_req, rc = -EPROTO);
        }

        lustre_get_wire_obdo(oa, &body->oa);

        /* This should really be sent by the OST */
        oa->o_blksize = PTLRPC_MAX_BRW_SIZE;
        oa->o_valid |= OBD_MD_FLBLKSZ;

        /* XXX LOV STACKING: the lsm that is passed to us from LOV does not
         * have valid lsm_oinfo data structs, so don't go touching that.
         * This needs to be fixed in a big way.
         */
        lsm->lsm_object_id = oa->o_id;
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

static int osc_punch_interpret(struct ptlrpc_request *req,
                               void *data, int rc)
{
        struct ost_body *body;
        struct osc_async_args *aa = data;
        ENTRY;

        if (rc != 0)
                GOTO(out, rc);

        body = lustre_swab_repbuf(req, REPLY_REC_OFF, sizeof (*body),
                                  lustre_swab_ost_body);
        if (body == NULL) {
                CERROR ("can't unpack ost_body\n");
                GOTO(out, rc = -EPROTO);
        }

        lustre_get_wire_obdo(aa->aa_oi->oi_oa, &body->oa);
out:
        rc = aa->aa_oi->oi_cb_up(aa->aa_oi, rc);
        RETURN(rc);
}

static int osc_punch(struct obd_export *exp, struct obd_info *oinfo,
                     struct obd_trans_info *oti,
                     struct ptlrpc_request_set *rqset)
{
        struct ptlrpc_request *req;
        struct osc_async_args *aa;
        struct ost_body *body;
        __u32 size[2] = { sizeof(struct ptlrpc_body), sizeof(*body) };
        ENTRY;

        if (!oinfo->oi_oa) {
                CERROR("oa NULL\n");
                RETURN(-EINVAL);
        }

        req = ptlrpc_prep_req(class_exp2cliimp(exp), LUSTRE_OST_VERSION,
                              OST_PUNCH, 2, size, NULL);
        if (!req)
                RETURN(-ENOMEM);

        req->rq_request_portal = OST_IO_PORTAL;         /* bug 7198 */
        ptlrpc_at_set_req_timeout(req);

        body = lustre_msg_buf(req->rq_reqmsg, REQ_REC_OFF, sizeof(*body));
        lustre_set_wire_obdo(&body->oa, oinfo->oi_oa);

        /* overload the size and blocks fields in the oa with start/end */
        body->oa.o_size = oinfo->oi_policy.l_extent.start;
        body->oa.o_blocks = oinfo->oi_policy.l_extent.end;
        body->oa.o_valid |= (OBD_MD_FLSIZE | OBD_MD_FLBLOCKS);

        ptlrpc_req_set_repsize(req, 2, size);

        req->rq_interpret_reply = osc_punch_interpret;
        CLASSERT(sizeof(*aa) <= sizeof(req->rq_async_args));
        aa = ptlrpc_req_async_args(req);
        aa->aa_oi = oinfo;
        ptlrpc_set_add_req(rqset, req);

        RETURN(0);
}

static int osc_sync_interpret(struct ptlrpc_request *req,
                              void *data, int rc)
{
        struct ost_body *body;
        struct osc_async_args *aa = data;
        ENTRY;

        if (rc)
                GOTO(out, rc);

        body = lustre_swab_repbuf(req, REPLY_REC_OFF, sizeof(*body),
                                  lustre_swab_ost_body);
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
        struct ost_body *body;
        __u32 size[2] = { sizeof(struct ptlrpc_body), sizeof(*body) };
        struct osc_async_args *aa;
        ENTRY;

        if (!oinfo->oi_oa) {
                CERROR("oa NULL\n");
                RETURN(-EINVAL);
        }

        req = ptlrpc_prep_req(class_exp2cliimp(exp), LUSTRE_OST_VERSION,
                              OST_SYNC, 2, size, NULL);
        if (!req)
                RETURN(-ENOMEM);

        body = lustre_msg_buf(req->rq_reqmsg, REQ_REC_OFF, sizeof(*body));
        lustre_set_wire_obdo(&body->oa, oinfo->oi_oa);

        /* overload the size and blocks fields in the oa with start/end */
        body->oa.o_size = start;
        body->oa.o_blocks = end;
        body->oa.o_valid |= (OBD_MD_FLSIZE | OBD_MD_FLBLOCKS);

        ptlrpc_req_set_repsize(req, 2, size);
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
                                   struct list_head *cancels, ldlm_mode_t mode,
                                   int lock_flags)
{
        struct ldlm_namespace *ns = exp->exp_obd->obd_namespace;
        struct ldlm_res_id res_id;
        struct ldlm_resource *res;
        int count;
        ENTRY;

        osc_build_res_name(oa->o_id, oa->o_gr, &res_id);
        res = ldlm_resource_get(ns, NULL, res_id, 0, 0);
        if (res == NULL)
                RETURN(0);

        count = ldlm_cancel_resource_local(res, cancels, NULL, mode,
                                           lock_flags, 0, NULL);
        ldlm_resource_putref(res);
        RETURN(count);
}

static int osc_destroy_interpret(struct ptlrpc_request *req, void *data,
                                 int rc)
{
        struct client_obd *cli = &req->rq_import->imp_obd->u.cli;

        atomic_dec(&cli->cl_destroy_in_flight);
        cfs_waitq_signal(&cli->cl_destroy_waitq);
        return 0;
}

static int osc_can_send_destroy(struct client_obd *cli)
{
        if (atomic_inc_return(&cli->cl_destroy_in_flight) <=
            cli->cl_max_rpcs_in_flight) {
                /* The destroy request can be sent */
                return 1;
        }
        if (atomic_dec_return(&cli->cl_destroy_in_flight) <
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
                       struct obd_export *md_export)
{
        CFS_LIST_HEAD(cancels);
        struct ptlrpc_request *req;
        struct ost_body *body;
        __u32 size[3] = { sizeof(struct ptlrpc_body), sizeof(*body),
                        sizeof(struct ldlm_request) };
        int count, bufcount = 2;
        struct client_obd *cli = &exp->exp_obd->u.cli;
        ENTRY;

        if (!oa) {
                CERROR("oa NULL\n");
                RETURN(-EINVAL);
        }

        LASSERT(oa->o_id != 0);

        count = osc_resource_get_unused(exp, oa, &cancels, LCK_PW,
                                        LDLM_FL_DISCARD_DATA);
        if (exp_connect_cancelset(exp))
                bufcount = 3;
        req = ldlm_prep_elc_req(exp, LUSTRE_OST_VERSION, OST_DESTROY, bufcount,
                                size, REQ_REC_OFF + 1, 0, &cancels, count);
        if (!req)
                RETURN(-ENOMEM);

        req->rq_request_portal = OST_IO_PORTAL;         /* bug 7198 */
        ptlrpc_at_set_req_timeout(req);

        body = lustre_msg_buf(req->rq_reqmsg, REQ_REC_OFF, sizeof(*body));

        if (oti != NULL && oa->o_valid & OBD_MD_FLCOOKIE) {
                oa->o_lcookie = *oti->oti_logcookies;
        }

        lustre_set_wire_obdo(&body->oa, oa);
        ptlrpc_req_set_repsize(req, 2, size);

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
        ptlrpcd_add_req(req);
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
        if (cli->cl_dirty > cli->cl_dirty_max) {
                CERROR("dirty %lu > dirty_max %lu\n",
                       cli->cl_dirty, cli->cl_dirty_max);
                oa->o_undirty = 0;
        } else if (atomic_read(&obd_dirty_pages) > obd_max_dirty_pages + 1) {
                /* The atomic_read() allowing the atomic_inc() are not covered
                 * by a lock thus they may safely race and trip this CERROR()
                 * unless we add in a small fudge factor (+1). */
                CERROR("dirty %d > system dirty_max %d\n",
                       atomic_read(&obd_dirty_pages), obd_max_dirty_pages);
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
static void osc_consume_write_grant(struct client_obd *cli,struct brw_page *pga)
{
        atomic_inc(&obd_dirty_pages);
        cli->cl_dirty += CFS_PAGE_SIZE;
        cli->cl_avail_grant -= CFS_PAGE_SIZE;
        pga->flag |= OBD_BRW_FROM_GRANT;
        CDEBUG(D_CACHE, "using %lu grant credits for brw %p page %p\n",
               CFS_PAGE_SIZE, pga, pga->pg);
        LASSERTF(cli->cl_avail_grant >= 0, "invalid avail grant is %ld \n",
                 cli->cl_avail_grant);
        osc_update_next_shrink(cli);
}

/* the companion to osc_consume_write_grant, called when a brw has completed.
 * must be called with the loi lock held. */
static void osc_release_write_grant(struct client_obd *cli,
                                    struct brw_page *pga, int sent)
{
        int blocksize = cli->cl_import->imp_obd->obd_osfs.os_bsize ? : 4096;
        ENTRY;

        if (!(pga->flag & OBD_BRW_FROM_GRANT)) {
                EXIT;
                return;
        }

        pga->flag &= ~OBD_BRW_FROM_GRANT;
        atomic_dec(&obd_dirty_pages);
        cli->cl_dirty -= CFS_PAGE_SIZE;
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
        struct list_head *l, *tmp;
        struct osc_cache_waiter *ocw;

        ENTRY;
        list_for_each_safe(l, tmp, &cli->cl_cache_waiters) {
                /* if we can't dirty more, we must wait until some is written */
                if ((cli->cl_dirty + CFS_PAGE_SIZE > cli->cl_dirty_max) ||
                   ((atomic_read(&obd_dirty_pages)+1)>(obd_max_dirty_pages))) {
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

                ocw = list_entry(l, struct osc_cache_waiter, ocw_entry);
                list_del_init(&ocw->ocw_entry);
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

static void osc_update_grant(struct client_obd *cli, struct ost_body *body)
{
        client_obd_list_lock(&cli->cl_loi_list_lock);
        CDEBUG(D_CACHE, "got "LPU64" extra grant\n", body->oa.o_grant);
        if (body->oa.o_valid & OBD_MD_FLGRANT)
                cli->cl_avail_grant += body->oa.o_grant;
        /* waiters are woken in brw_interpret */
        client_obd_list_unlock(&cli->cl_loi_list_lock);
}

static int osc_set_info_async(struct obd_export *exp, obd_count keylen,
                              void *key, obd_count vallen, void *val,
                              struct ptlrpc_request_set *set);

static int osc_shrink_grant_interpret(struct ptlrpc_request *req,
                                      void *data, int rc)
{
        struct osc_grant_args *aa = data;
        struct client_obd *cli = &req->rq_import->imp_obd->u.cli;
        struct obdo *oa = aa->aa_oa;
        struct ost_body *body;

        if (rc != 0) {
                client_obd_list_lock(&cli->cl_loi_list_lock);
                cli->cl_avail_grant += oa->o_grant;
                client_obd_list_unlock(&cli->cl_loi_list_lock);
                GOTO(out, rc);
        }
        body = lustre_swab_repbuf(req, REPLY_REC_OFF, sizeof(*oa),
                                lustre_swab_ost_body);
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
        if (rc) {
                client_obd_list_lock(&cli->cl_loi_list_lock);
                cli->cl_avail_grant += body->oa.o_grant;
                client_obd_list_unlock(&cli->cl_loi_list_lock);
        }
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

        list_for_each_entry(client, &item->ti_obd_list, cl_grant_shrink_list) {
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
         * ocd_grant is the total grant amount we're expect to hold: if we'v
         * been evicted, it's the new avail_grant amount, cl_dirty will drop
         * to 0 as inflight rpcs fail out; otherwise, it's avail_grant + dirty.
         *
         * race is tolerable here: if we're evicted, but imp_state already
         * left EVICTED state, then cl_diry must be 0 already.
         */
        client_obd_list_lock(&cli->cl_loi_list_lock);
        if (cli->cl_import->imp_state == LUSTRE_IMP_EVICTED)
                cli->cl_avail_grant = ocd->ocd_grant;
        else
                cli->cl_avail_grant = ocd->ocd_grant - cli->cl_dirty;

        if (cli->cl_avail_grant < 0) {
                CWARN("%s: available grant < 0, the OSS is probaly not running"
                      " with patch from bug 20278 (%ld)\n",
                      cli->cl_import->imp_obd->obd_name, cli->cl_avail_grant);
                /* workaround for 1.6 servers which do not have
                 * the patch from bug 20278 */
                cli->cl_avail_grant = ocd->ocd_grant;
        }
        client_obd_list_unlock(&cli->cl_loi_list_lock);

        CDEBUG(D_CACHE, "%s: setting cl_avail_grant: %ld cl_lost_grant: %ld \n",
               cli->cl_import->imp_obd->obd_name,
               cli->cl_avail_grant, cli->cl_lost_grant);

        if (ocd->ocd_connect_flags & OBD_CONNECT_GRANT_SHRINK &&
            list_empty(&cli->cl_grant_shrink_list))
                osc_add_shrink_grant(cli);
}

/* We assume that the reason this OSC got a short read is because it read
 * beyond the end of a stripe file; i.e. lustre is reading a sparse file
 * via the LOV, and it _knows_ it's reading inside the file, it's just that
 * this stripe never got written at or beyond this stripe offset yet. */
static void handle_short_read(int nob_read, obd_count page_count,
                              struct brw_page **pga, int pshift)
{
        char *ptr;
        int i = 0;

        /* skip bytes read OK */
        while (nob_read > 0) {
                LASSERT (page_count > 0);

                if (pga[i]->count > nob_read) {
                        /* EOF inside this page */
                        ptr = cfs_kmap(pga[i]->pg) +
                              (OSC_FILE2MEM_OFF(pga[i]->off,pshift)&~CFS_PAGE_MASK);
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
                ptr = cfs_kmap(pga[i]->pg) +
                      (OSC_FILE2MEM_OFF(pga[i]->off, pshift) & ~CFS_PAGE_MASK);
                memset(ptr, 0, pga[i]->count);
                cfs_kunmap(pga[i]->pg);
                i++;
        }
}

static int check_write_rcs(struct ptlrpc_request *req,
                           int requested_nob, int niocount,
                           obd_count page_count, struct brw_page **pga)
{
        int    *remote_rcs, i;

        /* return error if any niobuf was in error */
        remote_rcs = lustre_swab_repbuf(req, REQ_REC_OFF + 1,
                                        sizeof(*remote_rcs) * niocount, NULL);
        if (remote_rcs == NULL) {
                CERROR("Missing/short RC vector on BRW_WRITE reply\n");
                return(-EPROTO);
        }
        if (lustre_rep_need_swab(req))
                for (i = 0; i < niocount; i++)
                        __swab32s(&remote_rcs[i]);

        for (i = 0; i < niocount; i++) {
                if (remote_rcs[i] < 0)
                        return(remote_rcs[i]);

                if (remote_rcs[i] != 0) {
                        CERROR("rc[%d] invalid (%d) req %p\n",
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
                unsigned mask = ~(OBD_BRW_FROM_GRANT | OBD_BRW_ASYNC);

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
                                   cksum_type_t cksum_type, int pshift)
{
        __u32 cksum;
        int i = 0;

        LASSERT (pg_count > 0);
        cksum = init_checksum(cksum_type);
        while (nob > 0 && pg_count > 0) {
                unsigned char *ptr = cfs_kmap(pga[i]->pg);
                int off = OSC_FILE2MEM_OFF(pga[i]->off, pshift) & ~CFS_PAGE_MASK;
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
                                struct ptlrpc_request **reqp, int pshift,
                                int resend)
{
        struct ptlrpc_request   *req;
        struct ptlrpc_bulk_desc *desc;
        struct ost_body         *body;
        struct obd_ioobj        *ioobj;
        struct niobuf_remote    *niobuf;
        __u32 size[4] = { sizeof(struct ptlrpc_body), sizeof(*body) };
        int niocount, i, requested_nob, opc, rc;
        struct ptlrpc_request_pool *pool;
        struct osc_brw_async_args *aa;
        struct brw_page *pg_prev;

        ENTRY;
        OBD_FAIL_RETURN(OBD_FAIL_OSC_BRW_PREP_REQ, -ENOMEM); /* Recoverable */
        OBD_FAIL_RETURN(OBD_FAIL_OSC_BRW_PREP_REQ2, -EINVAL); /* Fatal */

        opc = ((cmd & OBD_BRW_WRITE) != 0) ? OST_WRITE : OST_READ;
        pool = ((cmd & OBD_BRW_WRITE) != 0) ? cli->cl_import->imp_rq_pool :NULL;

        for (niocount = i = 1; i < page_count; i++) {
                if (!can_merge_pages(pga[i - 1], pga[i]))
                        niocount++;
        }

        size[REQ_REC_OFF + 1] = sizeof(*ioobj);
        size[REQ_REC_OFF + 2] = niocount * sizeof(*niobuf);

        req = ptlrpc_prep_req_pool(cli->cl_import, LUSTRE_OST_VERSION, opc, 4, size,
                                   NULL, pool);
        if (req == NULL)
                RETURN (-ENOMEM);

        req->rq_request_portal = OST_IO_PORTAL;         /* bug 7198 */
        ptlrpc_at_set_req_timeout(req);
	/* ask ptlrpc not to resend on EINPROGRESS since BRWs have their own
	 * retry logic */
	req->rq_no_retry_einprogress = 1;

        if (opc == OST_WRITE)
                desc = ptlrpc_prep_bulk_imp (req, page_count,
                                             BULK_GET_SOURCE, OST_BULK_PORTAL);
        else
                desc = ptlrpc_prep_bulk_imp (req, page_count,
                                             BULK_PUT_SINK, OST_BULK_PORTAL);
        if (desc == NULL)
                GOTO(out, rc = -ENOMEM);
        /* NB request now owns desc and will free it when it gets freed */

        body = lustre_msg_buf(req->rq_reqmsg, REQ_REC_OFF, sizeof(*body));
        ioobj = lustre_msg_buf(req->rq_reqmsg, REQ_REC_OFF + 1, sizeof(*ioobj));
        niobuf = lustre_msg_buf(req->rq_reqmsg, REQ_REC_OFF + 2,
                                niocount * sizeof(*niobuf));

        lustre_set_wire_obdo(&body->oa, oa);
        obdo_to_ioobj(oa, ioobj);
        ioobj->ioo_bufcnt = niocount;

        LASSERT (page_count > 0);
        pg_prev = pga[0];
        for (requested_nob = i = 0; i < page_count; i++, niobuf++) {
                struct brw_page *pg = pga[i];

                LASSERT(pg->count > 0);
                LASSERTF((OSC_FILE2MEM_OFF(pg->off, pshift) & ~CFS_PAGE_MASK) +
                         pg->count <= CFS_PAGE_SIZE,
                         "i: %d pg: %p off: "LPU64", count: %u, shift: %d\n",
                         i, pg, pg->off, pg->count, pshift);
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

                ptlrpc_prep_bulk_page(desc, pg->pg,
                                      OSC_FILE2MEM_OFF(pg->off,pshift)&~CFS_PAGE_MASK,
                                      pg->count);
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
                lustre_msg_buf(req->rq_reqmsg, REQ_REC_OFF + 2,
                               niocount * sizeof(*niobuf)),
                "want %p - real %p\n", lustre_msg_buf(req->rq_reqmsg,
                REQ_REC_OFF + 2, niocount * sizeof(*niobuf)),
                (void *)(niobuf - niocount));

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
                if (cli->cl_checksum) {
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
                                                             cksum_type, pshift);
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
                size[REPLY_REC_OFF + 1] = sizeof(__u32) * niocount;
                ptlrpc_req_set_repsize(req, 3, size);
        } else {
                if (cli->cl_checksum) {
                        if ((body->oa.o_valid & OBD_MD_FLFLAGS) == 0)
                                body->oa.o_flags = 0;
                        body->oa.o_flags |= cksum_type_pack(cli->cl_cksum_type);
                        body->oa.o_valid |= OBD_MD_FLCKSUM | OBD_MD_FLFLAGS;
                }
                /* 1 RC for the whole I/O */
                ptlrpc_req_set_repsize(req, 2, size);
        }

        CLASSERT(sizeof(*aa) <= sizeof(req->rq_async_args));
        aa = ptlrpc_req_async_args(req);
        aa->aa_oa = oa;
        aa->aa_requested_nob = requested_nob;
        aa->aa_nio_count = niocount;
        aa->aa_page_count = page_count;
        aa->aa_resends = 0;
        aa->aa_ppga = pga;
        aa->aa_cli = cli;
        aa->aa_pshift = pshift;
        CFS_INIT_LIST_HEAD(&aa->aa_oaps);

        *reqp = req;
        RETURN (0);

 out:
        ptlrpc_req_finished (req);
        RETURN (rc);
}

static int check_write_checksum(struct obdo *oa, const lnet_process_id_t *peer,
                                __u32 client_cksum, __u32 server_cksum, int nob,
                                obd_count page_count, struct brw_page **pga,
                                cksum_type_t client_cksum_type, int pshift)
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
                                      cksum_type, pshift);

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

        LCONSOLE_ERROR_MSG(0x132, "BAD WRITE CHECKSUM: %s: from %s inum "
                           LPU64"/"LPU64" object "LPU64"/"LPU64" extent "
                           "["LPU64"-"LPU64"]\n",
                           msg, libcfs_nid2str(peer->nid),
                           oa->o_valid & OBD_MD_FLFID ? oa->o_fid : (__u64)0,
                           oa->o_valid & OBD_MD_FLFID ? oa->o_generation :
                                                        (__u64)0,
                           oa->o_id,
                           oa->o_valid & OBD_MD_FLGROUP ? oa->o_gr : (__u64)0,
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
        struct osc_brw_async_args *aa = ptlrpc_req_async_args(req);
        const lnet_process_id_t *peer =
                        &req->rq_import->imp_connection->c_peer;
        struct client_obd *cli = aa->aa_cli;
        struct ost_body *body;
        __u32 client_cksum = 0;
        ENTRY;

        if (rc < 0 && rc != -EDQUOT)
                RETURN(rc);

        LASSERTF(req->rq_repmsg != NULL, "rc = %d\n", rc);
        body = lustre_swab_repbuf(req, REPLY_REC_OFF, sizeof(*body),
                                  lustre_swab_ost_body);
        if (body == NULL) {
                CERROR ("Can't unpack body\n");
                RETURN(-EPROTO);
        }

        /* set/clear over quota flag for a uid/gid */
        if (lustre_msg_get_opc(req->rq_reqmsg) == OST_WRITE &&
            body->oa.o_valid & (OBD_MD_FLUSRQUOTA | OBD_MD_FLGRPQUOTA))
                lquota_setdq(quota_interface, cli, body->oa.o_uid,
                             body->oa.o_gid, body->oa.o_valid,
                             body->oa.o_flags);

        osc_update_grant(cli, body);

        if (rc < 0)
                RETURN(rc);

        if (aa->aa_oa->o_valid & OBD_MD_FLCKSUM)
                client_cksum = aa->aa_oa->o_cksum; /* save for later */

        if (lustre_msg_get_opc(req->rq_reqmsg) == OST_WRITE) {
                if (rc > 0) {
                        CERROR ("Unexpected +ve rc %d\n", rc);
                        RETURN(-EPROTO);
                }
                LASSERT(req->rq_bulk->bd_nob == aa->aa_requested_nob);

                if ((aa->aa_oa->o_valid & OBD_MD_FLCKSUM) && client_cksum &&
                    check_write_checksum(&body->oa, peer, client_cksum,
                                         body->oa.o_cksum, aa->aa_requested_nob,
                                         aa->aa_page_count, aa->aa_ppga,
                                         cksum_type_unpack(aa->aa_oa->o_flags),
                                         aa->aa_pshift))
                        RETURN(-EAGAIN);

                rc = check_write_rcs(req, aa->aa_requested_nob,aa->aa_nio_count,
                                     aa->aa_page_count, aa->aa_ppga);
                GOTO(out, rc);
        }

        /* The rest of this function executes only for OST_READs */
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
                handle_short_read(rc, aa->aa_page_count, aa->aa_ppga, aa->aa_pshift);

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
                                                 cksum_type, aa->aa_pshift);

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
                                           "%s%s%s inum "LPU64"/"LPU64" object "
                                           LPU64"/"LPU64" extent "
                                           "["LPU64"-"LPU64"]\n",
                                           req->rq_import->imp_obd->obd_name,
                                           libcfs_nid2str(peer->nid),
                                           via, router,
                                           body->oa.o_valid & OBD_MD_FLFID ?
                                                body->oa.o_fid : (__u64)0,
                                           body->oa.o_valid & OBD_MD_FLFID ?
                                                body->oa.o_generation :(__u64)0,
                                           body->oa.o_id,
                                           body->oa.o_valid & OBD_MD_FLGROUP ?
                                                body->oa.o_gr : (__u64)0,
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

static int osc_brw_internal(int cmd, struct obd_export *exp,struct obdo *oa,
                            struct lov_stripe_md *lsm,
                            obd_count page_count, struct brw_page **pga)
{
        struct ptlrpc_request *request;
        int                    rc;
        cfs_waitq_t            waitq;
        int                    generation, resends = 0;
        struct l_wait_info     lwi;

        ENTRY;
        init_waitqueue_head(&waitq);
        generation = exp->exp_obd->u.cli.cl_import->imp_generation;

restart_bulk:
        rc = osc_brw_prep_request(cmd, &exp->exp_obd->u.cli, oa, lsm,
                                  page_count, pga, &request, 0, resends);
        if (rc != 0)
                return (rc);

        if (resends) {
                request->rq_generation_set = 1;
                request->rq_import_generation = generation;
                request->rq_sent = CURRENT_SECONDS + resends;
        }

        rc = ptlrpc_queue_wait(request);

        if (rc == -ETIMEDOUT && request->rq_resend) {
                DEBUG_REQ(D_HA, request,  "BULK TIMEOUT");
                ptlrpc_req_finished(request);
                goto restart_bulk;
        }

        rc = osc_brw_fini_request(request, rc);

        ptlrpc_req_finished(request);
        /* When server return -EINPROGRESS, client should always retry
         * regardless of the number of times the bulk was resent already.*/
        if (osc_recoverable_error(rc)) {
                resends++;
                if (rc != -EINPROGRESS &&
                    !osc_should_resend(resends, &exp->exp_obd->u.cli)) {
                        CERROR("%s: too many resend retries for object: "
                               ""LPU64", rc = %d.\n",
                               exp->exp_obd->obd_name, oa->o_id, rc);
                        goto out;
                }
                if (generation !=
                    exp->exp_obd->u.cli.cl_import->imp_generation) {
                        CDEBUG(D_HA, "%s: resend cross eviction for object: "
                               ""LPU64", rc = %d.\n",
                               exp->exp_obd->obd_name, oa->o_id, rc);
                        goto out;
                }

                lwi = LWI_TIMEOUT_INTR(cfs_time_seconds(resends), NULL, NULL,
                                       NULL);
                l_wait_event(waitq, 0, &lwi);

                goto restart_bulk;
        }
out:
        if (rc == -EAGAIN || rc == -EINPROGRESS)
                rc = -EIO;
        RETURN (rc);
}

static int osc_brw_redo_request(struct ptlrpc_request *request,
				struct osc_brw_async_args *aa, int rc)
{
        struct ptlrpc_request *new_req;
        struct ptlrpc_request_set *set = request->rq_set;
        struct osc_brw_async_args *new_aa;
        struct osc_async_page *oap;
        ENTRY;

	DEBUG_REQ(rc == -EINPROGRESS ? D_RPCTRACE : D_ERROR, request,
		  "redo for recoverable error %d", rc);

        rc = osc_brw_prep_request(lustre_msg_get_opc(request->rq_reqmsg) ==
                                        OST_WRITE ? OBD_BRW_WRITE :OBD_BRW_READ,
                                  aa->aa_cli, aa->aa_oa,
                                  NULL /* lsm unused by osc currently */,
                                  aa->aa_page_count, aa->aa_ppga, &new_req,
                                  aa->aa_pshift, 1);
        if (rc)
                RETURN(rc);

        client_obd_list_lock(&aa->aa_cli->cl_loi_list_lock);

        list_for_each_entry(oap, &aa->aa_oaps, oap_rpc_item) {
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
	/* cap resend delay to the current request timeout, this is similar to
	 * what ptlrpc does (see after_reply()) */
	if (aa->aa_resends > new_req->rq_timeout)
		new_req->rq_sent = CURRENT_SECONDS + new_req->rq_timeout;
	else
		new_req->rq_sent = CURRENT_SECONDS  + aa->aa_resends;
        new_req->rq_generation_set = 1;
        new_req->rq_import_generation = request->rq_import_generation;

        new_aa = ptlrpc_req_async_args(new_req);

        CFS_INIT_LIST_HEAD(&new_aa->aa_oaps);
        list_splice(&aa->aa_oaps, &new_aa->aa_oaps);
        CFS_INIT_LIST_HEAD(&aa->aa_oaps);
        new_aa->aa_resends = aa->aa_resends;

        list_for_each_entry(oap, &new_aa->aa_oaps, oap_rpc_item) {
                if (oap->oap_request) {
                        ptlrpc_req_finished(oap->oap_request);
                        oap->oap_request = ptlrpc_request_addref(new_req);
                }
        }

        /* use ptlrpc_set_add_req is safe because interpret functions work
         * in check_set context. only one way exist with access to request
         * from different thread got -EINTR - this way protected with
         * cl_loi_list_lock */
        ptlrpc_set_add_req(set, new_req);

        client_obd_list_unlock(&aa->aa_cli->cl_loi_list_lock);

        DEBUG_REQ(D_INFO, new_req, "new request");
        RETURN(0);
}

static int async_internal(int cmd, struct obd_export *exp, struct obdo *oa,
                          struct lov_stripe_md *lsm, obd_count page_count,
                          struct brw_page **pga, struct ptlrpc_request_set *set,
                          int pshift)
{
        struct ptlrpc_request     *request;
        struct client_obd         *cli = &exp->exp_obd->u.cli;
        int                        rc, i;
        struct osc_brw_async_args *aa;
        ENTRY;

        /* Consume write credits even if doing a sync write -
         * otherwise we may run out of space on OST due to grant. */
        /* FIXME: unaligned writes must use write grants too */
        if (cmd == OBD_BRW_WRITE && pshift == 0) {
                client_obd_list_lock(&cli->cl_loi_list_lock);
                for (i = 0; i < page_count; i++) {
                        if (cli->cl_avail_grant >= CFS_PAGE_SIZE)
                                osc_consume_write_grant(cli, pga[i]);
                }
                client_obd_list_unlock(&cli->cl_loi_list_lock);
        }

        rc = osc_brw_prep_request(cmd, &exp->exp_obd->u.cli, oa, lsm,
                                  page_count, pga, &request, pshift, 0);

        CLASSERT(sizeof(*aa) <= sizeof(request->rq_async_args));

        if (rc == 0) {
                aa = ptlrpc_req_async_args(request);
                /* Do we need to separate dio stats? */
                if (cmd == OBD_BRW_READ) {
                        lprocfs_oh_tally_log2(&cli->cl_read_page_hist, page_count);
                        lprocfs_oh_tally(&cli->cl_read_rpc_hist, cli->cl_r_in_flight);
                } else {
                        lprocfs_oh_tally_log2(&cli->cl_write_page_hist, page_count);
                        lprocfs_oh_tally(&cli->cl_write_rpc_hist,
                                         cli->cl_w_in_flight);
                }
                ptlrpc_lprocfs_brw(request, aa->aa_requested_nob);

                LASSERT(list_empty(&aa->aa_oaps));

                request->rq_interpret_reply = brw_interpret;
                ptlrpc_set_add_req(set, request);

                client_obd_list_lock(&cli->cl_loi_list_lock);
                if (cmd == OBD_BRW_READ)
                        cli->cl_dio_r_in_flight++;
                else
                        cli->cl_dio_w_in_flight++;
                client_obd_list_unlock(&cli->cl_loi_list_lock);

                OBD_FAIL_TIMEOUT(OBD_FAIL_OSC_DIO_PAUSE, 3);
        } else if (cmd == OBD_BRW_WRITE) {
                client_obd_list_lock(&cli->cl_loi_list_lock);
                for (i = 0; i < page_count; i++)
                        osc_release_write_grant(cli, pga[i], 0);
                osc_wake_cache_waiters(cli);
                client_obd_list_unlock(&cli->cl_loi_list_lock);
        }

        RETURN (rc);
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
                        while (j >= stride && array[j-stride]->off > tmp->off) {
                                array[j] = array[j - stride];
                                j -= stride;
                        }
                        array[j] = tmp;
                }
        } while (stride > 1);
}

static obd_count max_unfragmented_pages(struct brw_page **pg, obd_count pages,
                                        int pshift)
{
        int count = 1;
        int offset;
        int i = 0;

        LASSERT (pages > 0);
        offset = OSC_FILE2MEM_OFF(pg[i]->off, pshift) & ~CFS_PAGE_MASK;

        for (;;) {
                pages--;
                if (pages == 0)         /* that's all */
                        return count;

                if (offset + pg[i]->count < CFS_PAGE_SIZE)
                        return count;   /* doesn't end on page boundary */

                i++;
                offset = OSC_FILE2MEM_OFF(pg[i]->off, pshift) & ~CFS_PAGE_MASK;
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

                pages_per_brw = max_unfragmented_pages(ppga, pages_per_brw, 0);

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
                                      pages_per_brw, ppga);

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

static int osc_brw_async(int cmd, struct obd_export *exp,
                         struct obd_info *oinfo, obd_count page_count,
                         struct brw_page *pga, struct obd_trans_info *oti,
                         struct ptlrpc_request_set *set, int pshift)
{
        struct brw_page **ppga, **orig;
        int page_count_orig;
        int rc = 0;
        ENTRY;

        if (cmd & OBD_BRW_CHECK) {
                /* The caller just wants to know if there's a chance that this
                 * I/O can succeed */
                struct obd_import *imp = class_exp2cliimp(exp);

                if (imp == NULL || imp->imp_invalid)
                        RETURN(-EIO);
                RETURN(0);
        }

        orig = ppga = osc_build_ppga(pga, page_count);
        if (ppga == NULL)
                RETURN(-ENOMEM);
        page_count_orig = page_count;

        sort_brw_pages(ppga, page_count);
        while (page_count) {
                struct brw_page **copy;
                struct obdo *oa;
                obd_count pages_per_brw;

                /* one page less under unaligned direct i/o */
                pages_per_brw = min_t(obd_count, page_count,
                    class_exp2cliimp(exp)->imp_obd->u.cli.cl_max_pages_per_rpc -
                                      !!pshift);

                pages_per_brw = max_unfragmented_pages(ppga, pages_per_brw,
                                                       pshift);

                /* use ppga only if single RPC is going to fly */
                if (pages_per_brw != page_count_orig || ppga != orig) {
                        OBD_ALLOC(copy, pages_per_brw * sizeof(*copy));
                        if (copy == NULL)
                                GOTO(out, rc = -ENOMEM);
                        memcpy(copy, ppga, pages_per_brw * sizeof(*copy));

                        OBDO_ALLOC(oa);
                        if (oa == NULL) {
                                OBD_FREE(copy, pages_per_brw * sizeof(*copy));
                                GOTO(out, rc = -ENOMEM);
                        }
                        memcpy(oa, oinfo->oi_oa, sizeof(*oa));
                        if (oa->o_valid & OBD_MD_FLFLAGS) {
                                oa->o_flags |= OBD_FL_TEMPORARY;
                        } else {
                                oa->o_valid |= OBD_MD_FLFLAGS;
                                oa->o_flags = OBD_FL_TEMPORARY;
                        }
                } else {
                        copy = ppga;
                        oa = oinfo->oi_oa;
                        LASSERT(!(oa->o_flags & OBD_FL_TEMPORARY));
                }

                rc = async_internal(cmd, exp, oa, oinfo->oi_md, pages_per_brw,
                                    copy, set, pshift);

                if (rc != 0) {
                        if (copy != ppga)
                                OBD_FREE(copy, pages_per_brw * sizeof(*copy));

                        if (oa->o_valid & OBD_MD_FLFLAGS &&
                            oa->o_flags & OBD_FL_TEMPORARY)
                                OBDO_FREE(oa);
                        break;
                }

                if (copy == orig) {
                        /* we passed it to async_internal() which is
                         * now responsible for releasing memory */
                        orig = NULL;
                }

                page_count -= pages_per_brw;
                ppga += pages_per_brw;
        }
out:
        if (orig)
                osc_release_ppga(orig, page_count_orig);
        RETURN(rc);
}

static void osc_check_rpcs(struct client_obd *cli);

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
        if (!list_empty(&lop->lop_urgent)) {
                CDEBUG(D_CACHE, "urgent request forcing RPC\n");
                RETURN(1);
        }

        /* fire off rpcs when we have 'optimal' rpcs as tuned for the wire. */
        optimal = cli->cl_max_pages_per_rpc;
        if (cmd & OBD_BRW_WRITE) {
                /* trigger a write rpc stream as long as there are dirtiers
                 * waiting for space.  as they're waiting, they're not going to
                 * create more pages to coalesce with what's waiting.. */
                if (!list_empty(&cli->cl_cache_waiters)) {
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

        if (list_empty(&lop->lop_urgent))
                RETURN(0);

        oap = list_entry(lop->lop_urgent.next,
                         struct osc_async_page, oap_urgent_item);

        if (oap->oap_async_flags & ASYNC_HP) {
                CDEBUG(D_CACHE, "hp request forcing RPC\n");
                RETURN(1);
        }

        RETURN(0);
}

static void on_list(struct list_head *item, struct list_head *list,
                    int should_be_on)
{
        if (list_empty(item) && should_be_on)
                list_add_tail(item, list);
        else if (!list_empty(item) && !should_be_on)
                list_del_init(item);
}

/* maintain the loi's cli list membership invariants so that osc_send_oap_rpc
 * can find pages to build into rpcs quickly */
static void loi_list_maint(struct client_obd *cli, struct lov_oinfo *loi)
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

/* this is called when a sync waiter receives an interruption.  Its job is to
 * get the caller woken as soon as possible.  If its page hasn't been put in an
 * rpc yet it can dequeue immediately.  Otherwise it has to mark the rpc as
 * desiring interruption which will forcefully complete the rpc once the rpc
 * has timed out */
static void osc_occ_interrupted(struct oig_callback_context *occ)
{
        struct osc_async_page *oap;
        struct loi_oap_pages *lop;
        struct lov_oinfo *loi;
        ENTRY;

        /* XXX member_of() */
        oap = list_entry(occ, struct osc_async_page, oap_occ);

        client_obd_list_lock(&oap->oap_cli->cl_loi_list_lock);

        oap->oap_interrupted = 1;

        /* ok, it's been put in an rpc. only one oap gets a request reference */
        if (oap->oap_request != NULL) {
                ptlrpc_mark_interrupted(oap->oap_request);
                ptlrpcd_wake(oap->oap_request);
                GOTO(unlock, 0);
        }

        /* we don't get interruption callbacks until osc_trigger_group_io()
         * has been called and put the sync oaps in the pending/urgent lists.*/
        if (!list_empty(&oap->oap_pending_item)) {
                list_del_init(&oap->oap_pending_item);
                list_del_init(&oap->oap_urgent_item);

                loi = oap->oap_loi;
                lop = (oap->oap_cmd & OBD_BRW_WRITE) ?
                        &loi->loi_write_lop : &loi->loi_read_lop;
                lop_update_pending(oap->oap_cli, lop, oap->oap_cmd, -1);
                loi_list_maint(oap->oap_cli, oap->oap_loi);

                oig_complete_one(oap->oap_oig, &oap->oap_occ, -EINTR);
                oap->oap_oig = NULL;
        }

unlock:
        client_obd_list_unlock(&oap->oap_cli->cl_loi_list_lock);
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

static void osc_oap_to_pending(struct osc_async_page *oap)
{
        struct loi_oap_pages *lop;

        if (oap->oap_cmd & OBD_BRW_WRITE)
                lop = &oap->oap_loi->loi_write_lop;
        else
                lop = &oap->oap_loi->loi_read_lop;

        if (oap->oap_async_flags & ASYNC_HP)
                list_add(&oap->oap_urgent_item, &lop->lop_urgent);
        else if (oap->oap_async_flags & ASYNC_URGENT)
                list_add_tail(&oap->oap_urgent_item, &lop->lop_urgent);
        list_add_tail(&oap->oap_pending_item, &lop->lop_pending);
        lop_update_pending(oap->oap_cli, lop, oap->oap_cmd, 1);
}

/* this must be called holding the loi list lock to give coverage to exit_cache,
 * async_flag maintenance, and oap_request */
static void osc_ap_completion(struct client_obd *cli, struct obdo *oa,
                              struct osc_async_page *oap, int sent, int rc)
{
        __u64 xid = 0;

        ENTRY;
        if (oap->oap_request != NULL) {
                xid = ptlrpc_req_xid(oap->oap_request);
                ptlrpc_req_finished(oap->oap_request);
                oap->oap_request = NULL;
        }

        spin_lock(&oap->oap_lock);
        oap->oap_async_flags = 0;
        spin_unlock(&oap->oap_lock);
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

        if (oap->oap_oig) {
                osc_exit_cache(cli, oap, sent);
                oig_complete_one(oap->oap_oig, &oap->oap_occ, rc);
                oap->oap_oig = NULL;
                EXIT;
                return;
        }

        rc = oap->oap_caller_ops->ap_completion(oap->oap_caller_data,
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

static int brw_interpret(struct ptlrpc_request *request, void *data, int rc)
{
        struct osc_brw_async_args *aa = data;
        struct client_obd *cli;
        ENTRY;

        rc = osc_brw_fini_request(request, rc);
        CDEBUG(D_INODE, "request %p aa %p rc %d\n", request, aa, rc);
        /* When server return -EINPROGRESS, client should always retry
         * regardless of the number of times the bulk was resent already. */
        if (osc_recoverable_error(rc)) {
                /* Only retry once for mmaped files since the mmaped page
                 * might be modified at anytime. We have to retry at least
                 * once in case there WAS really a corruption of the page
                 * on the network, that was not caused by mmap() modifying
                 * the page. bug 11742 */
                if ((rc == -EAGAIN) && (aa->aa_resends > 0) &&
                    aa->aa_oa->o_valid & OBD_MD_FLFLAGS &&
                    aa->aa_oa->o_flags & OBD_FL_MMAP) {
                        rc = 0;
                } else if (request->rq_import_generation !=
                           request->rq_import->imp_generation) {
                        CDEBUG(D_HA, "%s: resend cross eviction for object: "
                               ""LPU64", rc = %d.\n",
                               request->rq_import->imp_obd->obd_name,
                               aa->aa_oa->o_id, rc);
                        rc = -EIO;
                } else if (rc == -EINPROGRESS ||
                           osc_should_resend(aa->aa_resends, aa->aa_cli)) {
                        rc = osc_brw_redo_request(request, aa, rc);
                        if (rc == 0)
                                RETURN(0);
                } else {
                        CERROR("%s: too many resent retries for object: "
                               ""LPU64", rc = %d.\n",
                               request->rq_import->imp_obd->obd_name,
                               aa->aa_oa->o_id, rc);
                        rc = -EIO;
		}
        }

        cli = aa->aa_cli;
        client_obd_list_lock(&cli->cl_loi_list_lock);
        if (!list_empty(&aa->aa_oaps)) { /* from osc_send_oap_rpc() */
                struct osc_async_page *oap, *tmp;

                /* We need to decrement before osc_ap_completion->osc_wake_cache_waiters
                 * is called so we know whether to go to sync BRWs or wait for more
                 * RPCs to complete */
                if (lustre_msg_get_opc(request->rq_reqmsg) == OST_WRITE)
                        cli->cl_w_in_flight--;
                else
                        cli->cl_r_in_flight--;

                /* the caller may re-use the oap after the completion call so
                 * we need to clean it up a little */
                list_for_each_entry_safe(oap, tmp, &aa->aa_oaps, oap_rpc_item) {
                        list_del_init(&oap->oap_rpc_item);
                        osc_ap_completion(cli, aa->aa_oa, oap, 1, rc);
                }
                OBDO_FREE(aa->aa_oa);
        } else { /* from async_internal() */
                obd_count i;
                for (i = 0; i < aa->aa_page_count; i++)
                        osc_release_write_grant(aa->aa_cli, aa->aa_ppga[i], 1);

                if (aa->aa_oa->o_valid & OBD_MD_FLFLAGS &&
                    aa->aa_oa->o_flags & OBD_FL_TEMPORARY)
                        OBDO_FREE(aa->aa_oa);

                if (lustre_msg_get_opc(request->rq_reqmsg) == OST_WRITE)
                        cli->cl_dio_w_in_flight--;
                else
                        cli->cl_dio_r_in_flight--;
        }
        osc_wake_cache_waiters(cli);
        osc_check_rpcs(cli);
        client_obd_list_unlock(&cli->cl_loi_list_lock);

        osc_release_ppga(aa->aa_ppga, aa->aa_page_count);

        RETURN(rc);
}

static struct ptlrpc_request *osc_build_req(struct client_obd *cli,
                                            struct list_head *rpc_list,
                                            int page_count, int cmd)
{
        struct ptlrpc_request *req;
        struct brw_page **pga = NULL;
        struct osc_brw_async_args *aa;
        struct obdo *oa = NULL;
        struct obd_async_page_ops *ops = NULL;
        void *caller_data = NULL;
        struct osc_async_page *oap;
        struct ldlm_lock *lock = NULL;
        obd_valid valid;
        int i, rc, mpflag = 0;

        ENTRY;
        LASSERT(!list_empty(rpc_list));

        if (cmd & OBD_BRW_MEMALLOC)
                mpflag = libcfs_memory_pressure_get_and_set();

        OBD_ALLOC(pga, sizeof(*pga) * page_count);
        if (pga == NULL)
                RETURN(ERR_PTR(-ENOMEM));

        OBDO_ALLOC(oa);
        if (oa == NULL)
                GOTO(out, req = ERR_PTR(-ENOMEM));

        i = 0;
        list_for_each_entry(oap, rpc_list, oap_rpc_item) {
                if (ops == NULL) {
                        ops = oap->oap_caller_ops;
                        caller_data = oap->oap_caller_data;
                        lock = oap->oap_ldlm_lock;
                }
                pga[i] = &oap->oap_brw_page;
                pga[i]->off = oap->oap_obj_off + oap->oap_page_off;
                CDEBUG(0, "put page %p index %lu oap %p flg %x to pga\n",
                       pga[i]->pg, cfs_page_index(oap->oap_page), oap, pga[i]->flag);
                i++;
        }

        /* always get the data for the obdo for the rpc */
        LASSERT(ops != NULL);
        ops->ap_fill_obdo(caller_data, cmd, oa);
        if (lock) {
                oa->o_handle = lock->l_remote_handle;
                oa->o_valid |= OBD_MD_FLHANDLE;
        }

        sort_brw_pages(pga, page_count);
        rc = osc_brw_prep_request(cmd, cli, oa, NULL, page_count, pga, &req, 0,
                                  0);
        if (rc != 0) {
                CERROR("prep_req failed: %d\n", rc);
                GOTO(out, req = ERR_PTR(rc));
        }
        oa = &((struct ost_body *)lustre_msg_buf(req->rq_reqmsg, REQ_REC_OFF,
                                                 sizeof(struct ost_body)))->oa;

        if (cmd & OBD_BRW_MEMALLOC)
                req->rq_memalloc = 1;

        /* Need to update the timestamps after the request is built in case
         * we race with setattr (locally or in queue at OST).  If OST gets
         * later setattr before earlier BRW (as determined by the request xid),
         * the OST will not use BRW timestamps.  Sadly, there is no obvious
         * way to do this in a single call.  bug 10150 */
        if (pga[0]->flag & OBD_BRW_SRVLOCK) {
                /* in case of lockless read/write do not use inode's
                 * timestamps because concurrent stat might fill the
                 * inode with out-of-date times, send current
                 * instead */
                if (cmd & OBD_BRW_WRITE) {
                        oa->o_mtime = oa->o_ctime = LTIME_S(CURRENT_TIME);
                        oa->o_valid |= OBD_MD_FLMTIME | OBD_MD_FLCTIME;
                        valid = OBD_MD_FLATIME;
                } else {
                        oa->o_atime = LTIME_S(CURRENT_TIME);
                        oa->o_valid |= OBD_MD_FLATIME;
                        valid = OBD_MD_FLMTIME | OBD_MD_FLCTIME;
                }
        } else {
                valid = OBD_MD_FLMTIME | OBD_MD_FLCTIME | OBD_MD_FLATIME;
        }
        ops->ap_update_obdo(caller_data, cmd, oa, valid);

        CLASSERT(sizeof(*aa) <= sizeof(req->rq_async_args));
        aa = ptlrpc_req_async_args(req);
        CFS_INIT_LIST_HEAD(&aa->aa_oaps);
        list_splice(rpc_list, &aa->aa_oaps);
        CFS_INIT_LIST_HEAD(rpc_list);

out:
        if (cmd & OBD_BRW_MEMALLOC)
                libcfs_memory_pressure_restore(mpflag);

        if (IS_ERR(req)) {
                if (oa)
                        OBDO_FREE(oa);
                if (pga)
                        OBD_FREE(pga, sizeof(*pga) * page_count);
        }
        RETURN(req);
}

/* the loi lock is held across this function but it's allowed to release
 * and reacquire it during its work */
/**
 * prepare pages for ASYNC io and put pages in send queue.
 *
 * \param cli -
 * \param loi -
 * \param cmd - OBD_BRW_* macroses
 * \param lop - pending pages
 *
 * \return zero if no page added to send queue.
 * \return 1 if pages successfully added to send queue.
 * \return negative on errors.
 */
static int osc_send_oap_rpc(struct client_obd *cli, struct lov_oinfo *loi,
                            int cmd, struct loi_oap_pages *lop)
{
        struct ptlrpc_request *req;
        obd_count page_count = 0;
        struct osc_async_page *oap = NULL, *tmp;
        struct osc_brw_async_args *aa;
        struct obd_async_page_ops *ops;
        CFS_LIST_HEAD(rpc_list);
        unsigned int ending_offset;
        unsigned  starting_offset = 0;
        int srvlock = 0, mem_tight = 0;
        ENTRY;

        /* If there are HP OAPs we need to handle at least 1 of them,
         * move it the beginning of the pending list for that. */
        if (!list_empty(&lop->lop_urgent)) {
                oap = list_entry(lop->lop_urgent.next,
                                 struct osc_async_page, oap_urgent_item);
                if (oap->oap_async_flags & ASYNC_HP)
                        list_move(&oap->oap_pending_item, &lop->lop_pending);
        }

        /* first we find the pages we're allowed to work with */
        list_for_each_entry_safe(oap, tmp, &lop->lop_pending, oap_pending_item){
                ops = oap->oap_caller_ops;

                LASSERTF(oap->oap_magic == OAP_MAGIC, "Bad oap magic: oap %p, "
                         "magic 0x%x\n", oap, oap->oap_magic);

                if (page_count != 0 &&
                    srvlock != !!(oap->oap_brw_flags & OBD_BRW_SRVLOCK)) {
                        CDEBUG(D_PAGE, "SRVLOCK flag mismatch,"
                               " oap %p, page %p, srvlock %u\n",
                               oap, oap->oap_brw_page.pg, (unsigned)!srvlock);
                        break;
                }
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
                        int rc = ops->ap_make_ready(oap->oap_caller_data, cmd);
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
                                spin_lock(&oap->oap_lock);
                                oap->oap_async_flags |= ASYNC_COUNT_STABLE;
                                spin_unlock(&oap->oap_lock);
                                oap->oap_count = -EINTR;
                                break;
                        case 0:
                                spin_lock(&oap->oap_lock);
                                oap->oap_async_flags |= ASYNC_READY;
                                spin_unlock(&oap->oap_lock);
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
                 if(!(PageLocked(oap->oap_page) &&
                     (CheckWriteback(oap->oap_page, cmd) || oap->oap_oig !=NULL))) {
                        CDEBUG(D_PAGE, "page %p lost wb %lx/%x\n",
                               oap->oap_page, (long)oap->oap_page->flags, oap->oap_async_flags);
                        LBUG();
                }
#endif
                /* If there is a gap at the start of this page, it can't merge
                 * with any previous page, so we'll hand the network a
                 * "fragmented" page array that it can't transfer in 1 RDMA */
                if (page_count != 0 && oap->oap_page_off != 0)
                        break;

                /* take the page out of our book-keeping */
                list_del_init(&oap->oap_pending_item);
                lop_update_pending(cli, lop, cmd, -1);
                list_del_init(&oap->oap_urgent_item);

                if (page_count == 0)
                        starting_offset = (oap->oap_obj_off+oap->oap_page_off) &
                                          (PTLRPC_MAX_BRW_SIZE - 1);

                /* ask the caller for the size of the io as the rpc leaves. */
                if (!(oap->oap_async_flags & ASYNC_COUNT_STABLE))
                        oap->oap_count =
                                ops->ap_refresh_count(oap->oap_caller_data,cmd);
                if (oap->oap_count <= 0) {
                        CDEBUG(D_CACHE, "oap %p count %d, completing\n", oap,
                               oap->oap_count);
                        osc_ap_completion(cli, NULL, oap, 0, oap->oap_count);
                        continue;
                }

                /* now put the page back in our accounting */
                list_add_tail(&oap->oap_rpc_item, &rpc_list);
                if (oap->oap_brw_flags & OBD_BRW_MEMALLOC)
                        mem_tight = 1;
                if (page_count == 0)
                        srvlock = !!(oap->oap_brw_flags & OBD_BRW_SRVLOCK);
                if (++page_count >= cli->cl_max_pages_per_rpc)
                        break;

                /* End on a PTLRPC_MAX_BRW_SIZE boundary.  We want full-sized
                 * RPCs aligned on PTLRPC_MAX_BRW_SIZE boundaries to help reads
                 * have the same alignment as the initial writes that allocated
                 * extents on the server. */
                ending_offset = (oap->oap_obj_off + oap->oap_page_off +
                                 oap->oap_count) & (PTLRPC_MAX_BRW_SIZE - 1);
                if (ending_offset == 0)
                        break;

                /* If there is a gap at the end of this page, it can't merge
                 * with any subsequent pages, so we'll hand the network a
                 * "fragmented" page array that it can't transfer in 1 RDMA */
                if (oap->oap_page_off + oap->oap_count < CFS_PAGE_SIZE)
                        break;
        }

        osc_wake_cache_waiters(cli);

        if (page_count == 0)
                RETURN(0);

        loi_list_maint(cli, loi);

        client_obd_list_unlock(&cli->cl_loi_list_lock);

        req = osc_build_req(cli, &rpc_list, page_count,
                            mem_tight ? (cmd | OBD_BRW_MEMALLOC) : cmd);
        if (IS_ERR(req)) {
                /* this should happen rarely and is pretty bad, it makes the
                 * pending list not follow the dirty order */
                client_obd_list_lock(&cli->cl_loi_list_lock);
                list_for_each_entry_safe(oap, tmp, &rpc_list, oap_rpc_item) {
                        list_del_init(&oap->oap_rpc_item);

                        /* queued sync pages can be torn down while the pages
                         * were between the pending list and the rpc */
                        if (oap->oap_interrupted) {
                                CDEBUG(D_INODE, "oap %p interrupted\n", oap);
                                osc_ap_completion(cli, NULL, oap, 0,
                                                  oap->oap_count);
                                continue;
                        }
                        osc_ap_completion(cli, NULL, oap, 0, PTR_ERR(req));
                }
                loi_list_maint(cli, loi);
                RETURN(PTR_ERR(req));
        }

        aa = ptlrpc_req_async_args(req);
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
        list_for_each_entry(oap, &aa->aa_oaps, oap_rpc_item) {
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
        ptlrpcd_add_req(req);
        RETURN(1);
}

#define LOI_DEBUG(LOI, STR, args...)                                     \
        CDEBUG(D_INODE, "loi ready %d wr %d:%d rd %d:%d " STR,           \
               !list_empty(&(LOI)->loi_ready_item) ||                    \
               !list_empty(&(LOI)->loi_hp_ready_item),                   \
               (LOI)->loi_write_lop.lop_num_pending,                     \
               !list_empty(&(LOI)->loi_write_lop.lop_urgent),            \
               (LOI)->loi_read_lop.lop_num_pending,                      \
               !list_empty(&(LOI)->loi_read_lop.lop_urgent),             \
               args)                                                     \

/* This is called by osc_check_rpcs() to find which objects have pages that
 * we could be sending.  These lists are maintained by lop_makes_rpc(). */
struct lov_oinfo *osc_next_loi(struct client_obd *cli)
{
        ENTRY;
        /* First return objects that have blocked locks so that they
         * will be flushed quickly and other clients can get the lock,
         * then objects which have pages ready to be stuffed into RPCs */
        if (!list_empty(&cli->cl_loi_hp_ready_list))
                RETURN(list_entry(cli->cl_loi_hp_ready_list.next,
                                  struct lov_oinfo, loi_hp_ready_item));
        if (!list_empty(&cli->cl_loi_ready_list))
                RETURN(list_entry(cli->cl_loi_ready_list.next,
                                  struct lov_oinfo, loi_ready_item));

        /* then if we have cache waiters, return all objects with queued
         * writes.  This is especially important when many small files
         * have filled up the cache and not been fired into rpcs because
         * they don't pass the nr_pending/object threshhold */
        if (!list_empty(&cli->cl_cache_waiters) &&
            !list_empty(&cli->cl_loi_write_list))
                RETURN(list_entry(cli->cl_loi_write_list.next,
                                  struct lov_oinfo, loi_write_item));

        /* then return all queued objects when we have an invalid import
         * so that they get flushed */
        if (cli->cl_import == NULL || cli->cl_import->imp_invalid) {
                if (!list_empty(&cli->cl_loi_write_list))
                        RETURN(list_entry(cli->cl_loi_write_list.next,
                                          struct lov_oinfo, loi_write_item));
                if (!list_empty(&cli->cl_loi_read_list))
                        RETURN(list_entry(cli->cl_loi_read_list.next,
                                          struct lov_oinfo, loi_read_item));
        }
        RETURN(NULL);
}

static int osc_max_rpc_in_flight(struct client_obd *cli, struct lov_oinfo *loi)
{
        struct osc_async_page *oap;
        int hprpc = 0;

        if (!list_empty(&loi->loi_write_lop.lop_urgent)) {
                oap = list_entry(loi->loi_write_lop.lop_urgent.next,
                                 struct osc_async_page, oap_urgent_item);
                hprpc = !!(oap->oap_async_flags & ASYNC_HP);
        }

        if (!hprpc && !list_empty(&loi->loi_read_lop.lop_urgent)) {
                oap = list_entry(loi->loi_read_lop.lop_urgent.next,
                                 struct osc_async_page, oap_urgent_item);
                hprpc = !!(oap->oap_async_flags & ASYNC_HP);
        }

        return rpcs_in_flight(cli) >= cli->cl_max_rpcs_in_flight + hprpc;
}

/* called with the loi list lock held */
static void osc_check_rpcs(struct client_obd *cli)
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
                        rc = osc_send_oap_rpc(cli, loi, OBD_BRW_WRITE,
                                              &loi->loi_write_lop);
                        if (rc < 0)
                                break;
                        if (rc > 0)
                                race_counter = 0;
                        else
                                race_counter++;
                }
                if (lop_makes_rpc(cli, &loi->loi_read_lop, OBD_BRW_READ)) {
                        rc = osc_send_oap_rpc(cli, loi, OBD_BRW_READ,
                                              &loi->loi_read_lop);
                        if (rc < 0)
                                break;
                        if (rc > 0)
                                race_counter = 0;
                        else
                                race_counter++;
                }

                /* attempt some inter-object balancing by issuing rpcs
                 * for each object in turn */
                if (!list_empty(&loi->loi_hp_ready_item))
                        list_del_init(&loi->loi_hp_ready_item);
                if (!list_empty(&loi->loi_ready_item))
                        list_del_init(&loi->loi_ready_item);
                if (!list_empty(&loi->loi_write_item))
                        list_del_init(&loi->loi_write_item);
                if (!list_empty(&loi->loi_read_item))
                        list_del_init(&loi->loi_read_item);

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
        rc = list_empty(&ocw->ocw_entry) || rpcs_in_flight(cli) == 0;
        client_obd_list_unlock(&cli->cl_loi_list_lock);
        RETURN(rc);
};

/* Caller must hold loi_list_lock - we drop/regain it if we need to wait for
 * grant or cache space. */
static int osc_enter_cache(struct client_obd *cli, struct lov_oinfo *loi,
                           struct osc_async_page *oap)
{
        struct osc_cache_waiter ocw;
        struct l_wait_info lwi = LWI_INTR(LWI_ON_SIGNAL_NOOP, NULL);
        ENTRY;

        CDEBUG(D_CACHE, "dirty: %ld/%d dirty_max: %ld/%d dropped: %lu "
               "grant: %lu\n", cli->cl_dirty, atomic_read(&obd_dirty_pages),
               cli->cl_dirty_max, obd_max_dirty_pages,
               cli->cl_lost_grant, cli->cl_avail_grant);

        /* force the caller to try sync io.  this can jump the list
         * of queued writes and create a discontiguous rpc stream */
        if (cli->cl_dirty_max < CFS_PAGE_SIZE || cli->cl_ar.ar_force_sync ||
            loi->loi_ar.ar_force_sync)
                RETURN(-EDQUOT);

        /* Hopefully normal case - cache space and write credits available */
        if ((cli->cl_dirty + CFS_PAGE_SIZE <= cli->cl_dirty_max) &&
            (atomic_read(&obd_dirty_pages) + 1 <= obd_max_dirty_pages) &&
            (cli->cl_avail_grant >= CFS_PAGE_SIZE)) {
                /* account for ourselves */
                osc_consume_write_grant(cli, &oap->oap_brw_page);
                RETURN(0);
        }

        /* It is safe to block as a cache waiter as long as there is grant
         * space available or the hope of additional grant being returned
         * when an in flight write completes.  Using the write back cache
         * if possible is preferable to sending the data synchronously
         * because write pages can then be merged in to large requests.
         * The addition of this cache waiter will causing pending write
         * pages to be sent immediately. */
        if (cli->cl_w_in_flight || cli->cl_avail_grant >= CFS_PAGE_SIZE) {
                list_add_tail(&ocw.ocw_entry, &cli->cl_cache_waiters);
                cfs_waitq_init(&ocw.ocw_waitq);
                ocw.ocw_oap = oap;
                ocw.ocw_rc = 0;

                loi_list_maint(cli, loi);
                osc_check_rpcs(cli);
                client_obd_list_unlock(&cli->cl_loi_list_lock);

                CDEBUG(D_CACHE, "sleeping for cache space\n");
                l_wait_event(ocw.ocw_waitq, ocw_granted(cli, &ocw), &lwi);

                client_obd_list_lock(&cli->cl_loi_list_lock);
                if (!list_empty(&ocw.ocw_entry)) {
                        list_del(&ocw.ocw_entry);
                        RETURN(-EINTR);
                }
                RETURN(ocw.ocw_rc);
        }

        RETURN(-EDQUOT);
}

static int osc_get_lock(struct obd_export *exp, struct lov_stripe_md *lsm,
                        void **res, int rw, obd_off start, obd_off end,
                        struct lustre_handle *lockh, int flags)
{
        struct ldlm_lock *lock = NULL;
        int rc, release = 0;

        ENTRY;

        if (lockh && lustre_handle_is_used(lockh)) {
                /* if a valid lockh is passed, just check that the corresponding
                 * lock covers the extent */
                lock = ldlm_handle2lock(lockh);
                release = 1;
        } else {
                struct osc_async_page *oap = *res;
                spin_lock(&oap->oap_lock);
                lock = oap->oap_ldlm_lock;
                if (likely(lock))
                        LDLM_LOCK_GET(lock);
                spin_unlock(&oap->oap_lock);
        }
        /* lock can be NULL in case race obd_get_lock vs lock cancel
         * so we should be don't try match this */
        if (unlikely(!lock))
                return 0;

        rc = ldlm_lock_fast_match(lock, rw, start, end, lockh);
        if (release == 1 && rc == 1)
                /* if a valid lockh was passed, we just need to check
                 * that the lock covers the page, no reference should be
                 * taken*/
                ldlm_lock_decref(lockh,
                                 rw == OBD_BRW_WRITE ? LCK_PW : LCK_PR);
        LDLM_LOCK_PUT(lock);
        RETURN(rc);
}

int osc_prep_async_page(struct obd_export *exp, struct lov_stripe_md *lsm,
                        struct lov_oinfo *loi, cfs_page_t *page,
                        obd_off offset, struct obd_async_page_ops *ops,
                        void *data, void **res, int flags,
                        struct lustre_handle *lockh)
{
        struct osc_async_page *oap;
        struct ldlm_res_id oid = {{0}};
        int rc = 0;

        ENTRY;

        if (!page)
                return size_round(sizeof(*oap));

        oap = *res;
        oap->oap_magic = OAP_MAGIC;
        oap->oap_cli = &exp->exp_obd->u.cli;
        oap->oap_loi = loi;

        oap->oap_caller_ops = ops;
        oap->oap_caller_data = data;

        oap->oap_page = page;
        oap->oap_obj_off = offset;

        CFS_INIT_LIST_HEAD(&oap->oap_pending_item);
        CFS_INIT_LIST_HEAD(&oap->oap_urgent_item);
        CFS_INIT_LIST_HEAD(&oap->oap_rpc_item);
        CFS_INIT_LIST_HEAD(&oap->oap_page_list);

        oap->oap_occ.occ_interrupted = osc_occ_interrupted;

        spin_lock_init(&oap->oap_lock);

        /* If the page was marked as notcacheable - don't add to any locks */
        if (!(flags & OBD_PAGE_NO_CACHE)) {
                osc_build_res_name(loi->loi_id, loi->loi_gr, &oid);
                /* This is the only place where we can call cache_add_extent
                   without oap_lock, because this page is locked now, and
                   the lock we are adding it to is referenced, so cannot lose
                   any pages either. */
                rc = cache_add_extent(oap->oap_cli->cl_cache, &oid, oap, lockh);
                if (rc)
                        RETURN(rc);
        }

        CDEBUG(D_CACHE, "oap %p page %p obj off "LPU64"\n", oap, page, offset);
        RETURN(0);
}

struct osc_async_page *oap_from_cookie(void *cookie)
{
        struct osc_async_page *oap = cookie;
        if (oap->oap_magic != OAP_MAGIC)
                return ERR_PTR(-EINVAL);
        return oap;
};

static int osc_queue_async_io(struct obd_export *exp, struct lov_stripe_md *lsm,
                              struct lov_oinfo *loi, void *cookie,
                              int cmd, obd_off off, int count,
                              obd_flag brw_flags, enum async_flags async_flags)
{
        struct client_obd *cli = &exp->exp_obd->u.cli;
        struct osc_async_page *oap;
        int rc = 0;
        ENTRY;

        oap = oap_from_cookie(cookie);
        if (IS_ERR(oap))
                RETURN(PTR_ERR(oap));

        if (cli->cl_import == NULL || cli->cl_import->imp_invalid)
                RETURN(-EIO);

        if (!list_empty(&oap->oap_pending_item) ||
            !list_empty(&oap->oap_urgent_item) ||
            !list_empty(&oap->oap_rpc_item))
                RETURN(-EBUSY);

        /* check if the file's owner/group is over quota */
        if ((cmd & OBD_BRW_WRITE) && !(cmd & OBD_BRW_NOQUOTA)){
                struct obd_async_page_ops *ops;
                struct obdo *oa;

                OBDO_ALLOC(oa);
                if (oa == NULL)
                        RETURN(-ENOMEM);

                ops = oap->oap_caller_ops;
                ops->ap_fill_obdo(oap->oap_caller_data, cmd, oa);
                if (lquota_chkdq(quota_interface, cli, oa->o_uid, oa->o_gid) ==
                    NO_QUOTA)
                        rc = -EDQUOT;

                OBDO_FREE(oa);
                if (rc)
                        RETURN(rc);
        }

        if (loi == NULL)
                loi = lsm->lsm_oinfo[0];

        client_obd_list_lock(&cli->cl_loi_list_lock);

        oap->oap_cmd = cmd;
        oap->oap_page_off = off;
        oap->oap_count = count;
        oap->oap_brw_flags = brw_flags;
        /* Give a hint to OST that requests are coming from kswapd - bug19529 */
        if (libcfs_memory_pressure_get())
                oap->oap_brw_flags |= OBD_BRW_MEMALLOC;
        spin_lock(&oap->oap_lock);
        oap->oap_async_flags = async_flags;
        spin_unlock(&oap->oap_lock);

        if (cmd & OBD_BRW_WRITE) {
                rc = osc_enter_cache(cli, loi, oap);
                if (rc) {
                        client_obd_list_unlock(&cli->cl_loi_list_lock);
                        RETURN(rc);
                }
        }

        osc_oap_to_pending(oap);
        loi_list_maint(cli, loi);

        LOI_DEBUG(loi, "oap %p page %p added for cmd %d\n", oap, oap->oap_page,
                  cmd);

        osc_check_rpcs(cli);
        client_obd_list_unlock(&cli->cl_loi_list_lock);

        RETURN(0);
}

/* aka (~was & now & flag), but this is more clear :) */
#define SETTING(was, now, flag) (!(was & flag) && (now & flag))

static int osc_set_async_flags(struct obd_export *exp,
                               struct lov_stripe_md *lsm,
                               struct lov_oinfo *loi, void *cookie,
                               obd_flag async_flags)
{
        struct client_obd *cli = &exp->exp_obd->u.cli;
        struct loi_oap_pages *lop;
        struct osc_async_page *oap;
        int rc = 0;
        ENTRY;

        oap = oap_from_cookie(cookie);
        if (IS_ERR(oap))
                RETURN(PTR_ERR(oap));

        /*
         * bug 7311: OST-side locking is only supported for liblustre for now
         * (and liblustre never calls obd_set_async_flags(). I hope.), generic
         * implementation has to handle case where OST-locked page was picked
         * up by, e.g., ->writepage().
         */
        LASSERT(!(oap->oap_brw_flags & OBD_BRW_SRVLOCK));
        LASSERT(!LIBLUSTRE_CLIENT); /* check that liblustre angels do fear to
                                     * tread here. */

        if (cli->cl_import == NULL || cli->cl_import->imp_invalid)
                RETURN(-EIO);

        if (loi == NULL)
                loi = lsm->lsm_oinfo[0];

        if (oap->oap_cmd & OBD_BRW_WRITE) {
                lop = &loi->loi_write_lop;
        } else {
                lop = &loi->loi_read_lop;
        }

        client_obd_list_lock(&cli->cl_loi_list_lock);
        /* oap_lock provides atomic semantics of oap_async_flags access */
        spin_lock(&oap->oap_lock);
        if (list_empty(&oap->oap_pending_item))
                GOTO(out, rc = -EINVAL);

        if ((oap->oap_async_flags & async_flags) == async_flags)
                GOTO(out, rc = 0);

        if (SETTING(oap->oap_async_flags, async_flags, ASYNC_READY))
                oap->oap_async_flags |= ASYNC_READY;

        if (SETTING(oap->oap_async_flags, async_flags, ASYNC_URGENT) &&
            list_empty(&oap->oap_rpc_item)) {
                if (oap->oap_async_flags & ASYNC_HP)
                        list_add(&oap->oap_urgent_item, &lop->lop_urgent);
                else
                        list_add_tail(&oap->oap_urgent_item, &lop->lop_urgent);
                oap->oap_async_flags |= ASYNC_URGENT;
                loi_list_maint(cli, loi);
        }

        LOI_DEBUG(loi, "oap %p page %p has flags %x\n", oap, oap->oap_page,
                        oap->oap_async_flags);
out:
        spin_unlock(&oap->oap_lock);
        osc_check_rpcs(cli);
        client_obd_list_unlock(&cli->cl_loi_list_lock);
        RETURN(rc);
}

static int osc_queue_group_io(struct obd_export *exp, struct lov_stripe_md *lsm,
                             struct lov_oinfo *loi,
                             struct obd_io_group *oig, void *cookie,
                             int cmd, obd_off off, int count,
                             obd_flag brw_flags,
                             obd_flag async_flags)
{
        struct client_obd *cli = &exp->exp_obd->u.cli;
        struct osc_async_page *oap;
        struct loi_oap_pages *lop;
        int rc = 0;
        ENTRY;

        oap = oap_from_cookie(cookie);
        if (IS_ERR(oap))
                RETURN(PTR_ERR(oap));

        if (cli->cl_import == NULL || cli->cl_import->imp_invalid)
                RETURN(-EIO);

        if (!list_empty(&oap->oap_pending_item) ||
            !list_empty(&oap->oap_urgent_item) ||
            !list_empty(&oap->oap_rpc_item))
                RETURN(-EBUSY);

        if (loi == NULL)
                loi = lsm->lsm_oinfo[0];

        client_obd_list_lock(&cli->cl_loi_list_lock);

        oap->oap_cmd = cmd;
        oap->oap_page_off = off;
        oap->oap_count = count;
        oap->oap_brw_flags = brw_flags;
        /* Give a hint to OST that requests are coming from kswapd - bug19529 */
        if (libcfs_memory_pressure_get())
                oap->oap_brw_flags |= OBD_BRW_MEMALLOC;
        spin_lock(&oap->oap_lock);
        oap->oap_async_flags = async_flags;
        spin_unlock(&oap->oap_lock);

        if (cmd & OBD_BRW_WRITE)
                lop = &loi->loi_write_lop;
        else
                lop = &loi->loi_read_lop;

        list_add_tail(&oap->oap_pending_item, &lop->lop_pending_group);
        if (oap->oap_async_flags & ASYNC_GROUP_SYNC) {
                oap->oap_oig = oig;
                rc = oig_add_one(oig, &oap->oap_occ);
        }

        LOI_DEBUG(loi, "oap %p page %p on group pending: rc %d\n",
                  oap, oap->oap_page, rc);

        client_obd_list_unlock(&cli->cl_loi_list_lock);

        RETURN(rc);
}

static void osc_group_to_pending(struct client_obd *cli, struct lov_oinfo *loi,
                                 struct loi_oap_pages *lop, int cmd)
{
        struct list_head *pos, *tmp;
        struct osc_async_page *oap;

        list_for_each_safe(pos, tmp, &lop->lop_pending_group) {
                oap = list_entry(pos, struct osc_async_page, oap_pending_item);
                list_del(&oap->oap_pending_item);
                osc_oap_to_pending(oap);
        }
        loi_list_maint(cli, loi);
}

static int osc_trigger_group_io(struct obd_export *exp,
                                struct lov_stripe_md *lsm,
                                struct lov_oinfo *loi,
                                struct obd_io_group *oig)
{
        struct client_obd *cli = &exp->exp_obd->u.cli;
        ENTRY;

        if (loi == NULL)
                loi = lsm->lsm_oinfo[0];

        client_obd_list_lock(&cli->cl_loi_list_lock);

        osc_group_to_pending(cli, loi, &loi->loi_write_lop, OBD_BRW_WRITE);
        osc_group_to_pending(cli, loi, &loi->loi_read_lop, OBD_BRW_READ);

        osc_check_rpcs(cli);
        client_obd_list_unlock(&cli->cl_loi_list_lock);

        RETURN(0);
}

static int osc_teardown_async_page(struct obd_export *exp,
                                   struct lov_stripe_md *lsm,
                                   struct lov_oinfo *loi, void *cookie)
{
        struct client_obd *cli = &exp->exp_obd->u.cli;
        struct loi_oap_pages *lop;
        struct osc_async_page *oap;
        int rc = 0;
        ENTRY;

        oap = oap_from_cookie(cookie);
        if (IS_ERR(oap))
                RETURN(PTR_ERR(oap));

        if (loi == NULL)
                loi = lsm->lsm_oinfo[0];

        if (oap->oap_cmd & OBD_BRW_WRITE) {
                lop = &loi->loi_write_lop;
        } else {
                lop = &loi->loi_read_lop;
        }

        client_obd_list_lock(&cli->cl_loi_list_lock);

        if (!list_empty(&oap->oap_rpc_item))
                GOTO(out, rc = -EBUSY);

        osc_exit_cache(cli, oap, 0);
        osc_wake_cache_waiters(cli);

        if (!list_empty(&oap->oap_urgent_item)) {
                list_del_init(&oap->oap_urgent_item);
                spin_lock(&oap->oap_lock);
                oap->oap_async_flags &= ~(ASYNC_URGENT | ASYNC_HP);
                spin_unlock(&oap->oap_lock);
        }

        if (!list_empty(&oap->oap_pending_item)) {
                list_del_init(&oap->oap_pending_item);
                lop_update_pending(cli, lop, oap->oap_cmd, -1);
        }
        loi_list_maint(cli, loi);
        cache_remove_extent(cli->cl_cache, oap);

        LOI_DEBUG(loi, "oap %p page %p torn down\n", oap, oap->oap_page);
out:
        client_obd_list_unlock(&cli->cl_loi_list_lock);
        RETURN(rc);
}

int osc_extent_blocking_cb(struct ldlm_lock *lock,
                           struct ldlm_lock_desc *new, void *data,
                           int flag)
{
        struct lustre_handle lockh = { 0 };
        int rc;
        ENTRY;

        if ((unsigned long)data > 0 && (unsigned long)data < 0x1000) {
                LDLM_ERROR(lock, "cancelling lock with bad data %p", data);
                LBUG();
        }

        switch (flag) {
        case LDLM_CB_BLOCKING:
                ldlm_lock2handle(lock, &lockh);
                rc = ldlm_cli_cancel(&lockh);
                if (rc != ELDLM_OK)
                        CERROR("ldlm_cli_cancel failed: %d\n", rc);
                break;
        case LDLM_CB_CANCELING: {

                ldlm_lock2handle(lock, &lockh);
                /* This lock wasn't granted, don't try to do anything */
                if (lock->l_req_mode != lock->l_granted_mode)
                        RETURN(0);

                cache_remove_lock(lock->l_conn_export->exp_obd->u.cli.cl_cache,
                                  &lockh);

                if (lock->l_conn_export->exp_obd->u.cli.cl_ext_lock_cancel_cb)
                        lock->l_conn_export->exp_obd->u.cli.cl_ext_lock_cancel_cb(
                                                          lock, new, data,flag);
                break;
        }
        default:
                LBUG();
        }

        RETURN(0);
}
EXPORT_SYMBOL(osc_extent_blocking_cb);

static void osc_set_data_with_check(struct lustre_handle *lockh, void *data,
                                    int flags)
{
        struct ldlm_lock *lock = ldlm_handle2lock(lockh);

        if (lock == NULL) {
                CERROR("lockh %p, data %p - client evicted?\n", lockh, data);
                return;
        }
        lock_res_and_lock(lock);
#if defined (__KERNEL__) && defined (__linux__)
        /* Liang XXX: Darwin and Winnt checking should be added */
        if (lock->l_ast_data && lock->l_ast_data != data) {
                struct inode *new_inode = data;
                struct inode *old_inode = lock->l_ast_data;
                if (!(old_inode->i_state & I_FREEING))
                        LDLM_ERROR(lock, "inconsistent l_ast_data found");
                LASSERTF(old_inode->i_state & I_FREEING,
                         "Found existing inode %p/%lu/%u state %lu in lock: "
                         "setting data to %p/%lu/%u\n", old_inode,
                         old_inode->i_ino, old_inode->i_generation,
                         old_inode->i_state,
                         new_inode, new_inode->i_ino, new_inode->i_generation);
        }
#endif
        lock->l_ast_data = data;
        lock->l_flags |= (flags & LDLM_FL_NO_LRU);
        unlock_res_and_lock(lock);
        LDLM_LOCK_PUT(lock);
}

static int osc_change_cbdata(struct obd_export *exp, struct lov_stripe_md *lsm,
                             ldlm_iterator_t replace, void *data)
{
        struct ldlm_res_id res_id;
        struct obd_device *obd = class_exp2obd(exp);

        osc_build_res_name(lsm->lsm_object_id, lsm->lsm_object_gr, &res_id);
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

        osc_build_res_name(lsm->lsm_object_id, lsm->lsm_object_gr, &res_id);
        rc = ldlm_resource_iterate(obd->obd_namespace, &res_id, replace, data);
        if (rc == LDLM_ITER_STOP)
                return(1);
        if (rc == LDLM_ITER_CONTINUE)
                return(0);
        return(rc);
}

static int osc_enqueue_fini(struct obd_device *obd, struct ptlrpc_request *req,
                            struct obd_info *oinfo, int intent, int rc)
{
        ENTRY;

        if (intent) {
                /* The request was created before ldlm_cli_enqueue call. */
                if (rc == ELDLM_LOCK_ABORTED) {
                        struct ldlm_reply *rep;

                        /* swabbed by ldlm_cli_enqueue() */
                        LASSERT(lustre_rep_swabbed(req, DLM_LOCKREPLY_OFF));
                        rep = lustre_msg_buf(req->rq_repmsg, DLM_LOCKREPLY_OFF,
                                             sizeof(*rep));
                        LASSERT(rep != NULL);
                        if (rep->lock_policy_res1)
                                rc = rep->lock_policy_res1;
                }
        }

        if ((intent && rc == ELDLM_LOCK_ABORTED) || !rc) {
                CDEBUG(D_INODE,"got kms "LPU64" blocks "LPU64" mtime "LPU64"\n",
                       oinfo->oi_md->lsm_oinfo[0]->loi_lvb.lvb_size,
                       oinfo->oi_md->lsm_oinfo[0]->loi_lvb.lvb_blocks,
                       oinfo->oi_md->lsm_oinfo[0]->loi_lvb.lvb_mtime);
        }

        if (!rc)
                cache_add_lock(obd->u.cli.cl_cache, oinfo->oi_lockh);

        /* Call the update callback. */
        rc = oinfo->oi_cb_up(oinfo, rc);
        RETURN(rc);
}

static int osc_enqueue_interpret(struct ptlrpc_request *req,
                                 void *data, int rc)
{
        struct osc_enqueue_args *aa = data;
        int intent = aa->oa_oi->oi_flags & LDLM_FL_HAS_INTENT;
        struct lov_stripe_md *lsm = aa->oa_oi->oi_md;
        struct ldlm_lock *lock;

        /* ldlm_cli_enqueue is holding a reference on the lock, so it must
         * be valid. */
        lock = ldlm_handle2lock(aa->oa_oi->oi_lockh);

        /* Complete obtaining the lock procedure. */
        rc = ldlm_cli_enqueue_fini(aa->oa_exp, req, aa->oa_ei->ei_type, 1,
                                   aa->oa_ei->ei_mode,
                                   &aa->oa_oi->oi_flags,
                                   &lsm->lsm_oinfo[0]->loi_lvb,
                                   sizeof(lsm->lsm_oinfo[0]->loi_lvb),
                                   lustre_swab_ost_lvb,
                                   aa->oa_oi->oi_lockh, rc);

        /* Complete osc stuff. */
        rc = osc_enqueue_fini(aa->oa_exp->exp_obd, req, aa->oa_oi, intent, rc);

        /* Release the lock for async request. */
        if (lustre_handle_is_used(aa->oa_oi->oi_lockh) && rc == ELDLM_OK)
                ldlm_lock_decref(aa->oa_oi->oi_lockh, aa->oa_ei->ei_mode);

        LASSERTF(lock != NULL, "lockh %p, req %p, aa %p - client evicted?\n",
                 aa->oa_oi->oi_lockh, req, aa);
        LDLM_LOCK_PUT(lock);
        return rc;
}

/* When enqueuing asynchronously, locks are not ordered, we can obtain a lock
 * from the 2nd OSC before a lock from the 1st one. This does not deadlock with
 * other synchronous requests, however keeping some locks and trying to obtain
 * others may take a considerable amount of time in a case of ost failure; and
 * when other sync requests do not get released lock from a client, the client
 * is excluded from the cluster -- such scenarious make the life difficult, so
 * release locks just after they are obtained. */
static int osc_enqueue(struct obd_export *exp, struct obd_info *oinfo,
                       struct ldlm_enqueue_info *einfo,
                       struct ptlrpc_request_set *rqset)
{
        struct ldlm_res_id res_id;
        struct obd_device *obd = exp->exp_obd;
        struct ldlm_reply *rep;
        struct ptlrpc_request *req = NULL;
        int intent = oinfo->oi_flags & LDLM_FL_HAS_INTENT;
        ldlm_mode_t mode;
        int rc;
        ENTRY;

        osc_build_res_name(oinfo->oi_md->lsm_object_id,
                           oinfo->oi_md->lsm_object_gr, &res_id);
        /* Filesystem lock extents are extended to page boundaries so that
         * dealing with the page cache is a little smoother.  */
        oinfo->oi_policy.l_extent.start -=
                oinfo->oi_policy.l_extent.start & ~CFS_PAGE_MASK;
        oinfo->oi_policy.l_extent.end |= ~CFS_PAGE_MASK;

        if (oinfo->oi_md->lsm_oinfo[0]->loi_kms_valid == 0)
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
                               oinfo->oi_flags | LDLM_FL_LVB_READY, &res_id,
                               einfo->ei_type, &oinfo->oi_policy, mode,
                               oinfo->oi_lockh);
        if (mode) {
                /* addref the lock only if not async requests and PW lock is
                 * matched whereas we asked for PR. */
                if (!rqset && einfo->ei_mode != mode)
                        ldlm_lock_addref(oinfo->oi_lockh, LCK_PR);
                osc_set_data_with_check(oinfo->oi_lockh, einfo->ei_cbdata,
                                        oinfo->oi_flags);
                if (intent) {
                        /* I would like to be able to ASSERT here that rss <=
                         * kms, but I can't, for reasons which are explained in
                         * lov_enqueue() */
                }

                /* We already have a lock, and it's referenced */
                oinfo->oi_cb_up(oinfo, ELDLM_LOCK_MATCHED);

                /* For async requests, decref the lock. */
                if (einfo->ei_mode != mode)
                        ldlm_lock_decref(oinfo->oi_lockh, LCK_PW);
                else if (rqset)
                        ldlm_lock_decref(oinfo->oi_lockh, einfo->ei_mode);

                RETURN(ELDLM_OK);
        }

 no_match:
        if (intent) {
                __u32 size[3] = {
                        [MSG_PTLRPC_BODY_OFF] = sizeof(struct ptlrpc_body),
                        [DLM_LOCKREQ_OFF]     = sizeof(struct ldlm_request),
                        [DLM_LOCKREQ_OFF + 1] = 0 };

                req = ldlm_prep_enqueue_req(exp, 2, size, NULL, 0);
                if (req == NULL)
                        RETURN(-ENOMEM);

                size[DLM_LOCKREPLY_OFF] = sizeof(*rep);
                size[DLM_REPLY_REC_OFF] =
                        sizeof(oinfo->oi_md->lsm_oinfo[0]->loi_lvb);
                ptlrpc_req_set_repsize(req, 3, size);
        }

        /* users of osc_enqueue() can pass this flag for ldlm_lock_match() */
        oinfo->oi_flags &= ~LDLM_FL_BLOCK_GRANTED;

        rc = ldlm_cli_enqueue(exp, &req, einfo, res_id,
                              &oinfo->oi_policy, &oinfo->oi_flags,
                              &oinfo->oi_md->lsm_oinfo[0]->loi_lvb,
                              sizeof(oinfo->oi_md->lsm_oinfo[0]->loi_lvb),
                              lustre_swab_ost_lvb, oinfo->oi_lockh,
                              rqset ? 1 : 0);
        if (rqset) {
                if (!rc) {
                        struct osc_enqueue_args *aa;
                        CLASSERT(sizeof(*aa) <= sizeof(req->rq_async_args));
                        aa = ptlrpc_req_async_args(req);
                        aa->oa_oi = oinfo;
                        aa->oa_ei = einfo;
                        aa->oa_exp = exp;

                        req->rq_interpret_reply = osc_enqueue_interpret;
                        ptlrpc_set_add_req(rqset, req);
                } else if (intent) {
                        ptlrpc_req_finished(req);
                }
                RETURN(rc);
        }

        rc = osc_enqueue_fini(obd, req, oinfo, intent, rc);
        if (intent)
                ptlrpc_req_finished(req);

        RETURN(rc);
}

static int osc_match(struct obd_export *exp, struct lov_stripe_md *lsm,
                     __u32 type, ldlm_policy_data_t *policy, __u32 mode,
                     int *flags, void *data, struct lustre_handle *lockh,
                     int *n_matches)
{
        struct ldlm_res_id res_id;
        struct obd_device *obd = exp->exp_obd;
        int lflags = *flags;
        ldlm_mode_t rc;
        ENTRY;

        osc_build_res_name(lsm->lsm_object_id, lsm->lsm_object_gr, &res_id);

        OBD_FAIL_RETURN(OBD_FAIL_OSC_MATCH, -EIO);

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
        rc = ldlm_lock_match(obd->obd_namespace, lflags | LDLM_FL_LVB_READY,
                             &res_id, type, policy, rc, lockh);
        if (rc) {
                osc_set_data_with_check(lockh, data, lflags);
                if (!(lflags & LDLM_FL_TEST_LOCK) && mode != rc) {
                        ldlm_lock_addref(lockh, LCK_PR);
                        ldlm_lock_decref(lockh, LCK_PW);
                }
                if (n_matches != NULL)
                        (*n_matches)++;
        }

        RETURN(rc);
}

static int osc_cancel(struct obd_export *exp, struct lov_stripe_md *md,
                      __u32 mode, struct lustre_handle *lockh, int flags,
                      obd_off end)
{
        ENTRY;

        if (unlikely(mode == LCK_GROUP))
                ldlm_lock_decref_and_cancel(lockh, mode);
        else
                ldlm_lock_decref(lockh, mode);

        RETURN(0);
}

static int osc_cancel_unused(struct obd_export *exp,
                             struct lov_stripe_md *lsm, int flags, void *opaque)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct ldlm_res_id res_id, *resp = NULL;

        if (lsm != NULL) {
                resp = osc_build_res_name(lsm->lsm_object_id,
                                          lsm->lsm_object_gr, &res_id);
        }

        return ldlm_cli_cancel_unused(obd->obd_namespace, resp, flags, opaque);

}

static int osc_join_lru(struct obd_export *exp,
                        struct lov_stripe_md *lsm, int join)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct ldlm_res_id res_id, *resp = NULL;

        if (lsm != NULL) {
                resp = osc_build_res_name(lsm->lsm_object_id,
                                          lsm->lsm_object_gr, &res_id);
        }

        return ldlm_cli_join_lru(obd->obd_namespace, resp, join);

}

static int osc_statfs_interpret(struct ptlrpc_request *req,
                                void *data, int rc)
{
        struct osc_async_args *aa = data;
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

        msfs = lustre_swab_repbuf(req, REPLY_REC_OFF, sizeof(*msfs),
                                  lustre_swab_obd_statfs);
        if (msfs == NULL) {
                CERROR("Can't unpack obd_statfs\n");
                GOTO(out, rc = -EPROTO);
        }

        /* Reinitialize the RDONLY and DEGRADED flags at the client
         * on each statfs, so they don't stay set permanently. */
        spin_lock(&cli->cl_oscc.oscc_lock);

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
        used = min_t(__u64, (msfs->os_blocks - msfs->os_bfree) >> 10, 1 << 30);
        if (unlikely(((cli->cl_oscc.oscc_flags & OSCC_FLAG_NOSPC) == 0) &&
                     ((msfs->os_ffree < 32) || (msfs->os_bavail < used))))
                cli->cl_oscc.oscc_flags |= OSCC_FLAG_NOSPC;
        else if (unlikely(((cli->cl_oscc.oscc_flags & OSCC_FLAG_NOSPC) != 0) &&
                (msfs->os_ffree > 64) && (msfs->os_bavail > (used << 1))))
                        cli->cl_oscc.oscc_flags &= ~OSCC_FLAG_NOSPC;

        spin_unlock(&cli->cl_oscc.oscc_lock);

        memcpy(aa->aa_oi->oi_osfs, msfs, sizeof(*msfs));
out:
        rc = aa->aa_oi->oi_cb_up(aa->aa_oi, rc);
        RETURN(rc);
}

static int osc_statfs_async(struct obd_device *obd, struct obd_info *oinfo,
                            __u64 max_age, struct ptlrpc_request_set *rqset)
{
        struct ptlrpc_request *req;
        struct osc_async_args *aa;
        __u32 size[2] = { sizeof(struct ptlrpc_body), sizeof(*oinfo->oi_osfs) };
        ENTRY;

        /* We could possibly pass max_age in the request (as an absolute
         * timestamp or a "seconds.usec ago") so the target can avoid doing
         * extra calls into the filesystem if that isn't necessary (e.g.
         * during mount that would help a bit).  Having relative timestamps
         * is not so great if request processing is slow, while absolute
         * timestamps are not ideal because they need time synchronization. */
        req = ptlrpc_prep_req(obd->u.cli.cl_import, LUSTRE_OST_VERSION,
                              OST_STATFS, 1, NULL, NULL);
        if (!req)
                RETURN(-ENOMEM);

        ptlrpc_req_set_repsize(req, 2, size);
        req->rq_request_portal = OST_CREATE_PORTAL;
        ptlrpc_at_set_req_timeout(req);
        if (oinfo->oi_flags & OBD_STATFS_NODELAY) {
                /* procfs requests not want stat in wait for avoid deadlock */
                req->rq_no_resend = 1;
                req->rq_no_delay = 1;
        }

        req->rq_interpret_reply = osc_statfs_interpret;
        CLASSERT(sizeof(*aa) <= sizeof(req->rq_async_args));
        aa = ptlrpc_req_async_args(req);
        aa->aa_oi = oinfo;

        ptlrpc_set_add_req(rqset, req);
        RETURN(0);
}

static int osc_statfs(struct obd_device *obd, struct obd_statfs *osfs,
                      __u64 max_age, __u32 flags)
{
        struct obd_statfs *msfs;
        struct ptlrpc_request *req;
        struct obd_import     *imp = NULL;
        __u32 size[2] = { sizeof(struct ptlrpc_body), sizeof(*osfs) };
        int rc;
        ENTRY;

        /*Since the request might also come from lprocfs, so we need
         *sync this with client_disconnect_export Bug15684*/
        down_read(&obd->u.cli.cl_sem);
        if (obd->u.cli.cl_import)
                imp = class_import_get(obd->u.cli.cl_import);
        up_read(&obd->u.cli.cl_sem);
        if (!imp)
                RETURN(-ENODEV);

        /* We could possibly pass max_age in the request (as an absolute
         * timestamp or a "seconds.usec ago") so the target can avoid doing
         * extra calls into the filesystem if that isn't necessary (e.g.
         * during mount that would help a bit).  Having relative timestamps
         * is not so great if request processing is slow, while absolute
         * timestamps are not ideal because they need time synchronization. */
        req = ptlrpc_prep_req(imp, LUSTRE_OST_VERSION,
                              OST_STATFS, 1, NULL, NULL);

        class_import_put(imp);
        if (!req)
                RETURN(-ENOMEM);

        ptlrpc_req_set_repsize(req, 2, size);
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

        msfs = lustre_swab_repbuf(req, REPLY_REC_OFF, sizeof(*msfs),
                                  lustre_swab_obd_statfs);
        if (msfs == NULL) {
                CERROR("Can't unpack obd_statfs\n");
                GOTO(out, rc = -EPROTO);
        }

        memcpy(osfs, msfs, sizeof(*osfs));

        EXIT;
 out:
        ptlrpc_req_finished(req);
        return rc;
}

/* Retrieve object striping information.
 *
 * @lmmu is a pointer to an in-core struct with lmm_ost_count indicating
 * the maximum number of OST indices which will fit in the user buffer.
 * lmm_magic must be LOV_MAGIC_V1 or LOV_MAGIC_V3 (we only use 1 slot here).
 */
static int osc_getstripe(struct lov_stripe_md *lsm, struct lov_user_md *lump)
{
        /* we use lov_user_md_v3 because it is larger than lov_user_md_v1 */
        struct lov_user_md_v3 lum, *lumk;
        int rc = 0, lum_size;
        struct lov_user_ost_data_v1 *lmm_objects;
        ENTRY;

        if (!lsm)
                RETURN(-ENODATA);

        /* we only need the header part from user space to get lmm_magic and
         * lmm_stripe_count, (the header part is common to v1 and v3) */
        lum_size = sizeof(struct lov_user_md_v1);
        memset(&lum, 0x00, sizeof(lum));
        if (copy_from_user(&lum, lump, lum_size))
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

        lumk->lmm_magic = lum.lmm_magic;
        lumk->lmm_stripe_count = 1;
        lumk->lmm_object_id = lsm->lsm_object_id;

        if ((lsm->lsm_magic == LOV_USER_MAGIC_V1_SWABBED) ||
            (lsm->lsm_magic == LOV_USER_MAGIC_V3_SWABBED)) {
               /* lsm not in host order, so count also need be in same order */
                __swab32s(&lumk->lmm_magic);
                __swab16s(&lumk->lmm_stripe_count);
                lustre_swab_lov_user_md((struct lov_user_md_v1*)lumk);
                if (lum.lmm_stripe_count > 0)
                        lustre_swab_lov_user_md_objects(
                                (struct lov_user_md_v1*)lumk);
        }

        if (copy_to_user(lump, lumk, lum_size))
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

        if (!try_module_get(THIS_MODULE)) {
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

                err = copy_to_user((void *)uarg, buf, len);
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
        case OBD_IOC_DESTROY: {
                struct obdo            *oa;

                if (!cfs_capable(CFS_CAP_SYS_ADMIN))
                        GOTO (out, err = -EPERM);
                oa = &data->ioc_obdo1;

                if (oa->o_id == 0)
                        GOTO(out, err = -EINVAL);

                oa->o_valid |= OBD_MD_FLGROUP;

                err = osc_destroy(exp, oa, NULL, NULL, NULL);
                GOTO(out, err);
        }
        case OBD_IOC_PING_TARGET:
                err = ptlrpc_obd_ping(obd);
                GOTO(out, err);
        default:
                CDEBUG(D_INODE, "unrecognised ioctl %#x by %s\n",
                       cmd, cfs_curproc_comm());
                GOTO(out, err = -ENOTTY);
        }
out:
        module_put(THIS_MODULE);
        return err;
}

static int osc_get_info(struct obd_export *exp, obd_count keylen,
                        void *key, __u32 *vallen, void *val, struct lov_stripe_md *lsm)
{
        ENTRY;
        if (!vallen || !val)
                RETURN(-EFAULT);

        if (KEY_IS(KEY_LOCK_TO_STRIPE)) {
                __u32 *stripe = val;
                *vallen = sizeof(*stripe);
                *stripe = 0;
                RETURN(0);
        } else if (KEY_IS(KEY_OFF_RPCSIZE)) {
                struct client_obd *cli = &exp->exp_obd->u.cli;
                __u64 *rpcsize = val;
                LASSERT(*vallen == sizeof(__u64));
                *rpcsize = (__u64)cli->cl_max_pages_per_rpc;
                RETURN(0);
        } else if (KEY_IS(KEY_LAST_ID)) {
                struct ptlrpc_request *req;
                obd_id *reply;
                char *bufs[2] = { NULL, key };
                __u32 size[2] = { sizeof(struct ptlrpc_body), keylen };
                int rc;

                req = ptlrpc_prep_req(class_exp2cliimp(exp), LUSTRE_OST_VERSION,
                                      OST_GET_INFO, 2, size, bufs);
                if (req == NULL)
                        RETURN(-ENOMEM);

                size[REPLY_REC_OFF] = *vallen;
                ptlrpc_req_set_repsize(req, 2, size);
                rc = ptlrpc_queue_wait(req);
                if (rc)
                        GOTO(out, rc);

                reply = lustre_swab_repbuf(req, REPLY_REC_OFF, sizeof(*reply),
                                           lustre_swab_ost_last_id);
                if (reply == NULL) {
                        CERROR("Can't unpack OST last ID\n");
                        GOTO(out, rc = -EPROTO);
                }
                *((obd_id *)val) = *reply;
        out:
                ptlrpc_req_finished(req);
                RETURN(rc);
        } else if (KEY_IS(KEY_FIEMAP)) {
                struct ptlrpc_request *req;
                struct ll_user_fiemap *reply;
                char *bufs[2] = { NULL, key };
                __u32 size[2] = { sizeof(struct ptlrpc_body), keylen };
                int rc;

                req = ptlrpc_prep_req(class_exp2cliimp(exp), LUSTRE_OST_VERSION,
                                      OST_GET_INFO, 2, size, bufs);
                if (req == NULL)
                        RETURN(-ENOMEM);

                size[REPLY_REC_OFF] = *vallen;
                ptlrpc_req_set_repsize(req, 2, size);

                rc = ptlrpc_queue_wait(req);
                if (rc)
                        GOTO(out1, rc);
                reply = lustre_swab_repbuf(req, REPLY_REC_OFF, *vallen,
                                           lustre_swab_fiemap);
                if (reply == NULL) {
                        CERROR("Can't unpack FIEMAP reply.\n");
                        GOTO(out1, rc = -EPROTO);
                }

                memcpy(val, reply, *vallen);

        out1:
                ptlrpc_req_finished(req);

                RETURN(rc);
        }

        RETURN(-EINVAL);
}

static int osc_setinfo_mds_conn_interpret(struct ptlrpc_request *req,
                                          void *aa, int rc)
{
        struct llog_ctxt *ctxt;
        struct obd_import *imp = req->rq_import;
        ENTRY;

        if (rc != 0)
                RETURN(rc);

        ctxt = llog_get_context(imp->imp_obd, LLOG_MDS_OST_ORIG_CTXT);
        if (ctxt) {
                if (rc == 0)
                        rc = llog_initiator_connect(ctxt);
                else
                        CERROR("cannot establish connection for "
                               "ctxt %p: %d\n", ctxt, rc);
        }

        llog_ctxt_put(ctxt);
        spin_lock(&imp->imp_lock);
        imp->imp_server_timeout = 1;
        imp->imp_pingable = 1;
        spin_unlock(&imp->imp_lock);
        CDEBUG(D_RPCTRACE, "pinging OST %s\n", obd2cli_tgt(imp->imp_obd));

        RETURN(rc);
}

static int osc_set_info_async(struct obd_export *exp, obd_count keylen,
                              void *key, obd_count vallen, void *val,
                              struct ptlrpc_request_set *set)
{
        struct ptlrpc_request *req;
        struct obd_device  *obd = exp->exp_obd;
        struct obd_import *imp = class_exp2cliimp(exp);
        __u32 size[3] = { sizeof(struct ptlrpc_body), keylen, vallen };
        char *bufs[3] = { NULL, key, val };
        ENTRY;

        OBD_FAIL_TIMEOUT(OBD_FAIL_OSC_SHUTDOWN, 10);

        if (KEY_IS(KEY_NEXT_ID)) {
                obd_id new_val;
                struct osc_creator *oscc = &obd->u.cli.cl_oscc;

                if (vallen != sizeof(obd_id))
                        RETURN(-EINVAL);

                /* avoid race between allocate new object and set next id
                 * from ll_sync thread */
                spin_lock(&oscc->oscc_lock);
                new_val = *((obd_id*)val) + 1;
                if (new_val > oscc->oscc_next_id)
                        oscc->oscc_next_id = new_val;
                spin_unlock(&oscc->oscc_lock);

                CDEBUG(D_HA, "%s: set oscc_next_id = "LPU64"\n",
                       exp->exp_obd->obd_name,
                       oscc->oscc_next_id);

                RETURN(0);
        }

        if (KEY_IS(KEY_INIT_RECOV)) {
                if (vallen != sizeof(int))
                        RETURN(-EINVAL);
                spin_lock(&imp->imp_lock);
                imp->imp_initial_recov = *(int *)val;
                spin_unlock(&imp->imp_lock);
                CDEBUG(D_HA, "%s: set imp_initial_recov = %d\n",
                       exp->exp_obd->obd_name,
                       imp->imp_initial_recov);
                RETURN(0);
        }

        if (KEY_IS(KEY_CHECKSUM)) {
                if (vallen != sizeof(int))
                        RETURN(-EINVAL);
                exp->exp_obd->u.cli.cl_checksum = (*(int *)val) ? 1 : 0;
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

        req = ptlrpc_prep_req(imp, LUSTRE_OST_VERSION, OST_SET_INFO, 3, size,
                              bufs);
        if (req == NULL)
                RETURN(-ENOMEM);

        if (KEY_IS(KEY_MDS_CONN))
                req->rq_interpret_reply = osc_setinfo_mds_conn_interpret;
        else if (KEY_IS(KEY_GRANT_SHRINK))
                req->rq_interpret_reply = osc_shrink_grant_interpret;

        if (KEY_IS(KEY_GRANT_SHRINK)) {
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

                size[1] = vallen;
                ptlrpc_req_set_repsize(req, 2, size);
                ptlrpcd_add_req(req);
        } else {
                ptlrpc_req_set_repsize(req, 1, NULL);
                ptlrpc_set_add_req(set, req);
                ptlrpc_check_set(set);
        }

        RETURN(0);
}


static struct llog_operations osc_size_repl_logops = {
        lop_cancel: llog_obd_repl_cancel
};

static struct llog_operations osc_mds_ost_orig_logops;
static int osc_llog_init(struct obd_device *obd, struct obd_device *disk_obd,
                         int *index)
{
        struct llog_catid catid;
        static char name[32] = CATLIST;
        int rc;
        ENTRY;

        LASSERT(index);

        mutex_down(&disk_obd->obd_llog_cat_process);

        rc = llog_get_cat_list(disk_obd, disk_obd, name, *index, 1, &catid);
        if (rc) {
                CERROR("rc: %d\n", rc);
                GOTO(out_unlock, rc);
        }
#if 0
        CDEBUG(D_INFO, "%s: Init llog for %s/%d - catid "LPX64"/"LPX64":%x\n",
               obd->obd_name, uuid->uuid, idx, catid.lci_logid.lgl_oid,
               catid.lci_logid.lgl_ogr, catid.lci_logid.lgl_ogen);
#endif

        rc = llog_setup(obd, LLOG_MDS_OST_ORIG_CTXT, disk_obd, 1,
                        &catid.lci_logid, &osc_mds_ost_orig_logops);
        if (rc) {
                CERROR("failed LLOG_MDS_OST_ORIG_CTXT\n");
                GOTO (out, rc);
        }

        rc = llog_setup(obd, LLOG_SIZE_REPL_CTXT, disk_obd, 1, NULL,
                        &osc_size_repl_logops);
        if (rc) {
                struct llog_ctxt *ctxt =
                        llog_get_context(obd, LLOG_MDS_OST_ORIG_CTXT);
                if (ctxt)
                        llog_cleanup(ctxt);
                CERROR("failed LLOG_SIZE_REPL_CTXT\n");
        }
out:
        if (rc) {
                CERROR("osc '%s' tgt '%s' rc=%d\n",
                       obd->obd_name, disk_obd->obd_name, rc);
                CERROR("logid "LPX64":0x%x\n",
                       catid.lci_logid.lgl_oid, catid.lci_logid.lgl_ogen);
        } else {
                rc = llog_put_cat_list(disk_obd, disk_obd, name, *index, 1,
                                       &catid);
                if (rc)
                        CERROR("rc: %d\n", rc);
        }
out_unlock:
        mutex_up(&disk_obd->obd_llog_cat_process);

        RETURN(rc);
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

static int osc_reconnect(struct obd_export *exp, struct obd_device *obd,
                         struct obd_uuid *cluuid,
                         struct obd_connect_data *data,
                         void *localdata)
{
        struct client_obd *cli = &obd->u.cli;

        if (data != NULL && (data->ocd_connect_flags & OBD_CONNECT_GRANT)) {
                long lost_grant;

                client_obd_list_lock(&cli->cl_loi_list_lock);
                data->ocd_grant = cli->cl_avail_grant + cli->cl_dirty ?:
                                2 * cli->cl_max_pages_per_rpc << CFS_PAGE_SHIFT;
                lost_grant = cli->cl_lost_grant;
                cli->cl_lost_grant = 0;
                client_obd_list_unlock(&cli->cl_loi_list_lock);

                CDEBUG(D_CACHE, "request ocd_grant: %d cl_avail_grant: %ld "
                       "cl_dirty: %ld cl_lost_grant: %ld\n", data->ocd_grant,
                       cli->cl_dirty, cli->cl_avail_grant, lost_grant);
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

                        spin_lock(&oscc->oscc_lock);
                        oscc->oscc_flags |= OSCC_FLAG_RECOVERING;
                        spin_unlock(&oscc->oscc_lock);
                }
                cli = &obd->u.cli;
                client_obd_list_lock(&cli->cl_loi_list_lock);
                cli->cl_avail_grant = 0;
                cli->cl_lost_grant = 0;
                client_obd_list_unlock(&cli->cl_loi_list_lock);
                ptlrpc_import_setasync(imp, -1);

                break;
        }
        case IMP_EVENT_INACTIVE: {
                rc = obd_notify_observer(obd, obd, OBD_NOTIFY_INACTIVE, NULL);
                break;
        }
        case IMP_EVENT_INVALIDATE: {
                struct ldlm_namespace *ns = obd->obd_namespace;

                /* Reset grants */
                cli = &obd->u.cli;
                client_obd_list_lock(&cli->cl_loi_list_lock);
                /* all pages go to failing rpcs due to the invalid import */
                osc_check_rpcs(cli);
                client_obd_list_unlock(&cli->cl_loi_list_lock);

                ldlm_namespace_cleanup(ns, LDLM_FL_LOCAL_ONLY);

                break;
        }
        case IMP_EVENT_ACTIVE: {
                /* Only do this on the MDS OSC's */
                if (imp->imp_server_timeout) {
                        struct osc_creator *oscc = &obd->u.cli.cl_oscc;

                        spin_lock(&oscc->oscc_lock);
                        oscc->oscc_flags &= ~OSCC_FLAG_NOSPC;
                        spin_unlock(&oscc->oscc_lock);
                }
                CDEBUG(D_INFO, "notify server \n");
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

                ptlrpc_import_setasync(imp, 1);
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

/* determine whether the lock can be canceled before replaying the lock
 * during recovery, see bug16774 for detailed information 
 *
 * return values:
 *  zero  - the lock can't be canceled
 *  other - ok to cancel
 */
static int osc_cancel_for_recovery(struct ldlm_lock *lock)
{
        check_res_locked(lock->l_resource);
        if (lock->l_granted_mode == LCK_GROUP || 
            lock->l_resource->lr_type != LDLM_EXTENT)
                RETURN(0);

        /* cancel all unused extent locks with granted mode LCK_PR or LCK_CR */
        if (lock->l_granted_mode == LCK_PR ||
            lock->l_granted_mode == LCK_CR)
                RETURN(1);

        RETURN(0);       
}

int osc_setup(struct obd_device *obd, obd_count len, void *buf)
{
        int rc;
        ENTRY;

        ENTRY;
        rc = ptlrpcd_addref();
        if (rc)
                RETURN(rc);

        rc = client_obd_setup(obd, len, buf);
        if (rc) {
                ptlrpcd_decref();
        } else {
                struct lprocfs_static_vars lvars = { 0 };
                struct client_obd *cli = &obd->u.cli;

                cli->cl_grant_shrink_interval = GRANT_SHRINK_INTERVAL;
                lprocfs_osc_init_vars(&lvars);
                if (lprocfs_obd_setup(obd, lvars.obd_vars) == 0) {
                        lproc_osc_attach_seqstat(obd);
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
                cli->cl_cache = cache_create(obd);
                if (!cli->cl_cache) {
                        osc_cleanup(obd);
                        rc = -ENOMEM;
                }
                CFS_INIT_LIST_HEAD(&cli->cl_grant_shrink_list);
                sema_init(&cli->cl_grant_sem, 1);

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
                break;
        }
        case OBD_CLEANUP_EXPORTS: {
                /* If we set up but never connected, the
                   client import will not have been cleaned. */
                down_write(&obd->u.cli.cl_sem);
                if (obd->u.cli.cl_import) {
                        struct obd_import *imp;
                        imp = obd->u.cli.cl_import;
                        CDEBUG(D_CONFIG, "%s: client import never connected\n",
                               obd->obd_name);
                        ptlrpc_invalidate_import(imp);
                        if (imp->imp_rq_pool) {
                                ptlrpc_free_rq_pool(imp->imp_rq_pool);
                                imp->imp_rq_pool = NULL;
                        }
                        class_destroy_import(imp);
                        obd->u.cli.cl_import = NULL;
                }
                up_write(&obd->u.cli.cl_sem);

                rc = obd_llog_finish(obd, 0);
                if (rc != 0)
                        CERROR("failed to cleanup llogging subsystems\n");
                break;
        }
        case OBD_CLEANUP_SELF_EXP:
                break;
        case OBD_CLEANUP_OBD:
                break;
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

        cache_destroy(obd->u.cli.cl_cache);
        rc = client_obd_cleanup(obd);

        ptlrpcd_decref();
        RETURN(rc);
}

static int osc_register_page_removal_cb(struct obd_device *obd,
                                        obd_page_removal_cb_t func,
                                        obd_pin_extent_cb pin_cb)
{
        ENTRY;

        /* this server - not need init */
        if (func == NULL)
                return 0;

        return cache_add_extent_removal_cb(obd->u.cli.cl_cache, func,
                                           pin_cb);
}

static int osc_unregister_page_removal_cb(struct obd_device *obd,
                                          obd_page_removal_cb_t func)
{
        ENTRY;
        return cache_del_extent_removal_cb(obd->u.cli.cl_cache, func);
}

static int osc_register_lock_cancel_cb(struct obd_device *obd,
                                       obd_lock_cancel_cb cb)
{
        ENTRY;
        LASSERT(obd->u.cli.cl_ext_lock_cancel_cb == NULL);

        /* this server - not need init */
        if (cb == NULL)
                return 0;

        obd->u.cli.cl_ext_lock_cancel_cb = cb;
        return 0;
}

static int osc_unregister_lock_cancel_cb(struct obd_device *obd,
                                         obd_lock_cancel_cb cb)
{
        ENTRY;

        if (obd->u.cli.cl_ext_lock_cancel_cb != cb) {
                CERROR("Unregistering cancel cb %p, while only %p was "
                       "registered\n", cb,
                       obd->u.cli.cl_ext_lock_cancel_cb);
                RETURN(-EINVAL);
        }

        obd->u.cli.cl_ext_lock_cancel_cb = NULL;
        return 0;
}

static int osc_process_config(struct obd_device *obd, obd_count len, void *buf)
{
        struct lustre_cfg *lcfg = buf;
        struct lprocfs_static_vars lvars = { 0 };
        int rc = 0;

        lprocfs_osc_init_vars(&lvars);

        rc = class_process_proc_param(PARAM_OSC, lvars.obd_vars, lcfg, obd);
        return(rc);
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
        .o_brw_async            = osc_brw_async,
        .o_prep_async_page      = osc_prep_async_page,
        .o_get_lock             = osc_get_lock,
        .o_queue_async_io       = osc_queue_async_io,
        .o_set_async_flags      = osc_set_async_flags,
        .o_queue_group_io       = osc_queue_group_io,
        .o_trigger_group_io     = osc_trigger_group_io,
        .o_teardown_async_page  = osc_teardown_async_page,
        .o_punch                = osc_punch,
        .o_sync                 = osc_sync,
        .o_enqueue              = osc_enqueue,
        .o_match                = osc_match,
        .o_change_cbdata        = osc_change_cbdata,
        .o_find_cbdata          = osc_find_cbdata,
        .o_cancel               = osc_cancel,
        .o_cancel_unused        = osc_cancel_unused,
        .o_join_lru             = osc_join_lru,
        .o_iocontrol            = osc_iocontrol,
        .o_get_info             = osc_get_info,
        .o_set_info_async       = osc_set_info_async,
        .o_import_event         = osc_import_event,
        .o_llog_init            = osc_llog_init,
        .o_llog_finish          = osc_llog_finish,
        .o_process_config       = osc_process_config,
        .o_register_page_removal_cb = osc_register_page_removal_cb,
        .o_unregister_page_removal_cb = osc_unregister_page_removal_cb,
        .o_register_lock_cancel_cb = osc_register_lock_cancel_cb,
        .o_unregister_lock_cancel_cb = osc_unregister_lock_cancel_cb,
};
int __init osc_init(void)
{
        struct lprocfs_static_vars lvars = { 0 };
        int rc;
        ENTRY;

        lprocfs_osc_init_vars(&lvars);

        request_module("lquota");
        quota_interface = PORTAL_SYMBOL_GET(osc_quota_interface);
        lquota_init(quota_interface);
        init_obd_quota_ops(quota_interface, &osc_obd_ops);

        rc = class_register_type(&osc_obd_ops, lvars.module_vars,
                                 LUSTRE_OSC_NAME);
        if (rc) {
                if (quota_interface)
                        PORTAL_SYMBOL_PUT(osc_quota_interface);
                RETURN(rc);
        }

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
        lquota_exit(quota_interface);
        if (quota_interface)
                PORTAL_SYMBOL_PUT(osc_quota_interface);

        class_unregister_type(LUSTRE_OSC_NAME);
}

MODULE_AUTHOR("Sun Microsystems, Inc. <http://www.lustre.org/>");
MODULE_DESCRIPTION("Lustre Object Storage Client (OSC)");
MODULE_LICENSE("GPL");

cfs_module(osc, LUSTRE_VERSION_STRING, osc_init, osc_exit);
#endif
