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
 * Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */
#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_LQUOTA

#ifdef __KERNEL__
# include <linux/version.h>
# include <linux/module.h>
# include <linux/init.h>
# include <linux/fs.h>
# include <linux/quota.h>
#  include <linux/smp_lock.h>
#  include <linux/buffer_head.h>
#  include <linux/workqueue.h>
#  include <linux/mount.h>
#else /* __KERNEL__ */
# include <liblustre.h>
#endif

#include <obd_class.h>
#include <lustre_mds.h>
#include <lustre_dlm.h>
#include <lustre_cfg.h>
#include <obd_ost.h>
#include <lustre_fsfilt.h>
#include <lustre_quota.h>
#include "quota_internal.h"

#ifdef HAVE_QUOTA_SUPPORT
#ifdef __KERNEL__

/* When quotaon, build a lqs for every uid/gid who has been set limitation
 * for quota. After quota_search_lqs, it will hold one ref for the lqs.
 * It will be released when qctxt_cleanup() is executed b=18574 */
void build_lqs(struct obd_device *obd)
{
        struct lustre_quota_ctxt *qctxt = &obd->u.obt.obt_qctxt;
        struct list_head id_list;
        int i, rc;

        INIT_LIST_HEAD(&id_list);
        for (i = 0; i < MAXQUOTAS; i++) {
                struct dquot_id *dqid, *tmp;

                if (sb_dqopt(qctxt->lqc_sb)->files[i] == NULL)
                        continue;

#ifndef KERNEL_SUPPORTS_QUOTA_READ
                rc = fsfilt_qids(obd, sb_dqopt(qctxt->lqc_sb)->files[i], NULL,
                                 i, &id_list);
#else
                rc = fsfilt_qids(obd, NULL, sb_dqopt(qctxt->lqc_sb)->files[i],
                                 i, &id_list);
#endif
                if (rc) {
                        CERROR("%s: failed to get %s qids\n", obd->obd_name,
                               i ? "group" : "user");
                        continue;
                }

                list_for_each_entry_safe(dqid, tmp, &id_list,
                                         di_link) {
                        struct lustre_qunit_size *lqs;

                        list_del_init(&dqid->di_link);
                        lqs = quota_search_lqs(LQS_KEY(i, dqid->di_id),
                                               qctxt, 1);
                        if (lqs && !IS_ERR(lqs)) {
                                lqs->lqs_flags |= dqid->di_flag;
                                lqs_putref(lqs);
                        } else {
                                CERROR("%s: failed to create a lqs for %sid %u"
                                       "\n", obd->obd_name, i ? "g" : "u",
                                       dqid->di_id);
                        }

                        OBD_FREE_PTR(dqid);
                }
        }
}

int mds_quota_ctl(struct obd_export *exp, struct obd_quotactl *oqctl)
{
        struct obd_device *obd = exp->exp_obd;
        struct obd_device_target *obt = &obd->u.obt;
        struct lustre_quota_ctxt *qctxt = &obd->u.obt.obt_qctxt;
        struct timeval work_start;
        struct timeval work_end;
        long timediff;
        int rc = 0;
        ENTRY;

        do_gettimeofday(&work_start);
        switch (oqctl->qc_cmd) {
        case Q_QUOTAON:
                rc = mds_quota_on(obd, oqctl);
                break;
        case Q_QUOTAOFF:
                oqctl->qc_id = obt->obt_qfmt; /* override qfmt version */
                mds_quota_off(obd, oqctl);
                break;
        case Q_SETINFO:
                rc = mds_set_dqinfo(obd, oqctl);
                break;
        case Q_GETINFO:
                rc = mds_get_dqinfo(obd, oqctl);
                break;
        case Q_SETQUOTA:
                rc = mds_set_dqblk(obd, oqctl);
                break;
        case Q_GETQUOTA:
                rc = mds_get_dqblk(obd, oqctl);
                break;
        case Q_GETOINFO:
        case Q_GETOQUOTA:
                rc = mds_get_obd_quota(obd, oqctl);
                break;
        case LUSTRE_Q_INVALIDATE:
                rc = mds_quota_invalidate(obd, oqctl);
                break;
        case LUSTRE_Q_FINVALIDATE:
                oqctl->qc_id = obt->obt_qfmt; /* override qfmt version */
                rc = mds_quota_finvalidate(obd, oqctl);
                break;
        default:
                CERROR("%s: unsupported mds_quotactl command: %d\n",
                       obd->obd_name, oqctl->qc_cmd);
                RETURN(-EFAULT);
        }

        if (rc)
                CDEBUG(D_INFO, "mds_quotactl admin quota command %d, id %u, "
                               "type %d, failed: rc = %d\n",
                       oqctl->qc_cmd, oqctl->qc_id, oqctl->qc_type, rc);
        do_gettimeofday(&work_end);
        timediff = cfs_timeval_sub(&work_end, &work_start, NULL);
        lprocfs_counter_add(qctxt->lqc_stats, LQUOTA_QUOTA_CTL, timediff);

        RETURN(rc);
}

int filter_quota_ctl(struct obd_export *exp, struct obd_quotactl *oqctl)
{
        struct obd_device *obd = exp->exp_obd;
        struct obd_device_target *obt = &obd->u.obt;
        struct lvfs_run_ctxt saved;
        struct lustre_quota_ctxt *qctxt = &obd->u.obt.obt_qctxt;
        struct lustre_qunit_size *lqs;
        void *handle = NULL;
        struct timeval work_start;
        struct timeval work_end;
        long timediff;
        int rc = 0;
        ENTRY;

        do_gettimeofday(&work_start);
        switch (oqctl->qc_cmd) {
        case Q_QUOTAON:
                oqctl->qc_id = obt->obt_qfmt;
                rc = generic_quota_on(obd, oqctl, 0);
                break;
        case Q_FINVALIDATE:
        case Q_QUOTAOFF:
                if (!atomic_dec_and_test(&obt->obt_quotachecking)) {
                        CDEBUG(D_INFO, "other people are doing quotacheck\n");
                        atomic_inc(&obt->obt_quotachecking);
                        rc = -EBUSY;
                        break;
                }
                if (oqctl->qc_cmd == Q_FINVALIDATE &&
                    (obt->obt_qctxt.lqc_flags & UGQUOTA2LQC(oqctl->qc_type))) {
                        atomic_inc(&obt->obt_quotachecking);
                        rc = -EBUSY;
                        break;
                }
                oqctl->qc_id = obt->obt_qfmt; /* override qfmt version */
        case Q_GETOINFO:
        case Q_GETOQUOTA:
        case Q_GETQUOTA:
                /* In recovery scenario, this pending dqacq/dqrel might have
                 * been processed by master successfully before it's dquot
                 * on master enter recovery mode. We must wait for this 
                 * dqacq/dqrel done then return the correct limits to master */
                if (oqctl->qc_stat == QUOTA_RECOVERING)
                        handle = quota_barrier(&obd->u.obt.obt_qctxt, oqctl, 1);

                push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
                rc = fsfilt_quotactl(obd, obt->obt_sb, oqctl);
                pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);

                if (oqctl->qc_stat == QUOTA_RECOVERING)
                        quota_unbarrier(handle);

                if (oqctl->qc_cmd == Q_QUOTAOFF ||
                    oqctl->qc_cmd == Q_FINVALIDATE) {
                        if (!rc && oqctl->qc_cmd == Q_QUOTAOFF) {
                                obt->obt_qctxt.lqc_flags &= ~UGQUOTA2LQC(oqctl->qc_type);
                                CDEBUG(D_QUOTA, "%s: quotaoff type:flags:rc "
                                       "%u:%lu:%d\n", obd->obd_name,
                                       oqctl->qc_type, qctxt->lqc_flags, rc);
                        }
                        atomic_inc(&obt->obt_quotachecking);
                }
                break;
        case Q_SETQUOTA:
                /* currently, it is only used for nullifying the quota */
                handle = quota_barrier(&obd->u.obt.obt_qctxt, oqctl, 1);

                push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
                rc = fsfilt_quotactl(obd, obd->u.obt.obt_sb, oqctl);

                if (!rc) {
                        oqctl->qc_cmd = Q_SYNC;
                        fsfilt_quotactl(obd, obd->u.obt.obt_sb, oqctl);
                        oqctl->qc_cmd = Q_SETQUOTA;
                }
                pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
                quota_unbarrier(handle);

                lqs = quota_search_lqs(LQS_KEY(oqctl->qc_type, oqctl->qc_id),
                                       qctxt, 0);
                if (lqs == NULL || IS_ERR(lqs)){
                        CERROR("fail to create lqs during setquota operation "
                               "for %sid %u\n", oqctl->qc_type ? "g" : "u",
                               oqctl->qc_id);
                } else {
                        lqs->lqs_flags &= ~QB_SET;
                        lqs_putref(lqs);
                }

                break;
        case Q_INITQUOTA:
                {
                unsigned int uid = 0, gid = 0;

                /* Initialize quota limit to MIN_QLIMIT */
                LASSERT(oqctl->qc_dqblk.dqb_valid == QIF_BLIMITS);
                LASSERT(oqctl->qc_dqblk.dqb_bsoftlimit == 0);

                if (!oqctl->qc_dqblk.dqb_bhardlimit)
                        goto adjust;

               /* There might be a pending dqacq/dqrel (which is going to
                 * clear stale limits on slave). we should wait for it's
                 * completion then initialize limits */
                handle = quota_barrier(&obd->u.obt.obt_qctxt, oqctl, 1);
                LASSERT(oqctl->qc_dqblk.dqb_bhardlimit == MIN_QLIMIT);
                push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
                rc = fsfilt_quotactl(obd, obd->u.obt.obt_sb, oqctl);

                /* Update on-disk quota, in case of lose the changed limits
                 * (MIN_QLIMIT) on crash, which cannot be recovered.*/
                if (!rc) {
                        oqctl->qc_cmd = Q_SYNC;
                        fsfilt_quotactl(obd, obd->u.obt.obt_sb, oqctl);
                        oqctl->qc_cmd = Q_INITQUOTA;
                }
                pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
                quota_unbarrier(handle);

                if (rc)
                        RETURN(rc);
adjust:
                lqs = quota_search_lqs(LQS_KEY(oqctl->qc_type, oqctl->qc_id),
                                       qctxt, 1);
                if (lqs == NULL || IS_ERR(lqs)){
                        CERROR("fail to create lqs during setquota operation "
                               "for %sid %u\n", oqctl->qc_type ? "g" : "u",
                               oqctl->qc_id);
                        break;
                } else {
                        lqs->lqs_flags |= QB_SET;
                        if (OBD_FAIL_CHECK(OBD_FAIL_QUOTA_WITHOUT_CHANGE_QS)) {
                                lqs->lqs_bunit_sz = qctxt->lqc_bunit_sz;
                                lqs->lqs_btune_sz = qctxt->lqc_btune_sz;
                                lqs->lqs_iunit_sz = qctxt->lqc_iunit_sz;
                                lqs->lqs_itune_sz = qctxt->lqc_itune_sz;
                        }
                        lqs_putref(lqs);
                }

                /* Trigger qunit pre-acquire */
                if (oqctl->qc_type == USRQUOTA)
                        uid = oqctl->qc_id;
                else
                        gid = oqctl->qc_id;

                rc = qctxt_adjust_qunit(obd, &obd->u.obt.obt_qctxt,
                                        uid, gid, 1, 0, NULL);
                if (rc == -EDQUOT || rc == -EBUSY) {
                        CDEBUG(D_QUOTA, "rc: %d.\n", rc);
                        rc = 0;
                }

                break;
                }
        default:
                CERROR("%s: unsupported filter_quotactl command: %d\n",
                       obd->obd_name, oqctl->qc_cmd);
                RETURN(-EFAULT);
        }
        do_gettimeofday(&work_end);
        timediff = cfs_timeval_sub(&work_end, &work_start, NULL);
        lprocfs_counter_add(qctxt->lqc_stats, LQUOTA_QUOTA_CTL, timediff);

        RETURN(rc);
}
#endif /* __KERNEL__ */
#endif

int client_quota_ctl(struct obd_export *exp, struct obd_quotactl *oqctl)
{
        struct ptlrpc_request *req;
        struct obd_quotactl *oqc;
        __u32 size[2] = { sizeof(struct ptlrpc_body), sizeof(*oqctl) };
        int ver, opc, rc;
        ENTRY;

        if (!strcmp(exp->exp_obd->obd_type->typ_name, LUSTRE_MDC_NAME)) {
                ver = LUSTRE_MDS_VERSION,
                opc = MDS_QUOTACTL;
        } else if (!strcmp(exp->exp_obd->obd_type->typ_name, LUSTRE_OSC_NAME)) {
                ver = LUSTRE_OST_VERSION,
                opc = OST_QUOTACTL;
        } else {
                RETURN(-EINVAL);
        }

        req = ptlrpc_prep_req(class_exp2cliimp(exp), ver, opc, 2, size, NULL);
        if (!req)
                GOTO(out, rc = -ENOMEM);

        oqc = lustre_msg_buf(req->rq_reqmsg, REQ_REC_OFF, sizeof(*oqctl));
        *oqc = *oqctl;

        ptlrpc_req_set_repsize(req, 2, size);
        ptlrpc_at_set_req_timeout(req);
        req->rq_no_resend = 1;

        rc = ptlrpc_queue_wait(req);
        if (rc) {
                CERROR("ptlrpc_queue_wait failed, rc: %d\n", rc);
                GOTO(out, rc);
        }

        if (req->rq_repmsg) {
                oqc = lustre_swab_repbuf(req, REPLY_REC_OFF, sizeof(*oqc),
                                         lustre_swab_obd_quotactl);
                if (oqc != NULL) {
                        *oqctl = *oqc;
                } else {
                        CERROR ("Can't unpack obd_quotactl\n");
                        rc = -EPROTO;
                }
        }
        EXIT;
out:
        ptlrpc_req_finished(req);
        return rc;
}

struct lov_getquota_set_arg {
        __u64 curspace;
        __u64 bhardlimit;
};

static int lov_getquota_interpret(struct ptlrpc_request_set *rqset, void *data, int rc)
{
        struct lov_getquota_set_arg *set_arg = data;
        struct ptlrpc_request *req;
        struct list_head *pos;
        struct obd_quotactl *oqc;

        list_for_each(pos, &rqset->set_requests) {
                req = list_entry(pos, struct ptlrpc_request, rq_set_chain);

                if (req->rq_status)
                        continue;

                oqc = NULL;
                if (req->rq_repmsg)
                        oqc = lustre_swab_repbuf(req, REPLY_REC_OFF, sizeof(*oqc),
                                lustre_swab_obd_quotactl);

                if (oqc == NULL) {
                        CERROR("Can't unpack obd_quotactl\n");
                        rc = -EPROTO;
                        continue;
                }

                set_arg->curspace += oqc->qc_dqblk.dqb_curspace;
                set_arg->bhardlimit += oqc->qc_dqblk.dqb_bhardlimit;
        }

        return rc;
}

int lov_quota_ctl(struct obd_export *exp, struct obd_quotactl *oqctl)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct lov_obd *lov = &obd->u.lov;
        int i, rc = 0, rc1;
        struct lov_getquota_set_arg set_arg = { 0 };
        struct obd_export *ltd_exp;
        struct ptlrpc_request_set *rqset;
        __u32 size[2] = { sizeof(struct ptlrpc_body), sizeof(*oqctl) };

        ENTRY;

        if (oqctl->qc_cmd != LUSTRE_Q_QUOTAON &&
            oqctl->qc_cmd != LUSTRE_Q_QUOTAOFF &&
            oqctl->qc_cmd != Q_GETOQUOTA &&
            oqctl->qc_cmd != Q_INITQUOTA &&
            oqctl->qc_cmd != LUSTRE_Q_SETQUOTA &&
            oqctl->qc_cmd != Q_FINVALIDATE) {
                CERROR("bad quota opc %x for lov obd", oqctl->qc_cmd);
                RETURN(-EINVAL);
        }

        rqset = ptlrpc_prep_set();
        if (rqset == NULL)
                RETURN(-ENOMEM);

        obd_getref(obd);

        for (i = 0; i < lov->desc.ld_tgt_count; i++) {
                struct ptlrpc_request *req;
                struct obd_quotactl *oqc;

                if (!lov->lov_tgts[i])
                        continue;

                if (!lov->lov_tgts[i]->ltd_active) {
                        /* Skip Q_GETOQUOTA on administratively disabled OSTs.
                         */
                        if (oqctl->qc_cmd == Q_GETOQUOTA &&
                            lov->lov_tgts[i]->ltd_activate) {
                                CERROR("ost %d is inactive\n", i);
                                rc = -EIO;
                        } else {
                                CDEBUG(D_HA, "ost %d is inactive\n", i);
                        }
                        continue;
                }

                ltd_exp = lov->lov_tgts[i]->ltd_exp;

                req = ptlrpc_prep_req(class_exp2cliimp(ltd_exp),
                                      LUSTRE_OST_VERSION,
                                      OST_QUOTACTL, 2, size, NULL);
                if (!req) {
                        obd_putref(obd);
                        GOTO(out, rc = -ENOMEM);
                }

                oqc = lustre_msg_buf(req->rq_reqmsg, REQ_REC_OFF, sizeof(*oqctl));
                *oqc = *oqctl;

                ptlrpc_req_set_repsize(req, 2, size);
                ptlrpc_at_set_req_timeout(req);
                req->rq_no_resend = 1;
                req->rq_no_delay = 1;

                ptlrpc_set_add_req(rqset, req);
        }

        obd_putref(obd);

        if (oqctl->qc_cmd == Q_GETOQUOTA) {
                rqset->set_interpret = lov_getquota_interpret;
                rqset->set_arg = &set_arg;
        }
        rc1 = ptlrpc_set_wait(rqset);
        rc = rc1 ? rc1 : rc;

out:
        ptlrpc_set_destroy(rqset);
        oqctl->qc_dqblk.dqb_curspace = set_arg.curspace;
        oqctl->qc_dqblk.dqb_bhardlimit = set_arg.bhardlimit;

        RETURN(rc);
}
