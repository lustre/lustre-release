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
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
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
#include <linux/lustre_quota.h>
#include <class_hash.h>
#include "quota_internal.h"

#ifdef HAVE_QUOTA_SUPPORT

#ifdef __KERNEL__
/* this function is charge of recording lqs_ino_rec and
 * lqs_blk_rec. when a lquota slave checks a quota
 * request(check_cur_qunit) and finishes a quota
 * request(dqacq_completion), it will be called.
 * is_chk: whether it is checking quota; otherwise, it is finishing
 * is_acq: whether it is acquiring; otherwise, it is releasing
 */
void quota_compute_lqs(struct qunit_data *qdata, struct lustre_qunit_size *lqs,
                       int is_chk, int is_acq)
{
        long long *rec;

        LASSERT(qdata && lqs);
        LASSERT_SPIN_LOCKED(&lqs->lqs_lock);

        rec = QDATA_IS_BLK(qdata) ? &lqs->lqs_blk_rec : &lqs->lqs_ino_rec;

        if (!!is_chk + !!is_acq == 1)
                *rec -= qdata->qd_count;
        else
                *rec += qdata->qd_count;

}

static struct lustre_qunit_size *
quota_create_lqs(unsigned long long lqs_key, struct lustre_quota_ctxt *qctxt)
{
        struct lustre_qunit_size *lqs = NULL;
        int rc = 0;

        OBD_ALLOC_PTR(lqs);
        if (!lqs)
                GOTO(out, rc = -ENOMEM);

        lqs->lqs_key = lqs_key;

        spin_lock_init(&lqs->lqs_lock);
        lqs->lqs_bwrite_pending = 0;
        lqs->lqs_iwrite_pending = 0;
        lqs->lqs_ino_rec = 0;
        lqs->lqs_blk_rec = 0;
        lqs->lqs_id = LQS_KEY_ID(lqs->lqs_key);
        lqs->lqs_flags = LQS_KEY_GRP(lqs->lqs_key) ? LQUOTA_FLAGS_GRP : 0;
        lqs->lqs_bunit_sz = qctxt->lqc_bunit_sz;
        lqs->lqs_iunit_sz = qctxt->lqc_iunit_sz;
        lqs->lqs_btune_sz = qctxt->lqc_btune_sz;
        lqs->lqs_itune_sz = qctxt->lqc_itune_sz;
        lqs->lqs_ctxt = qctxt;
        if (qctxt->lqc_handler) {
                lqs->lqs_last_bshrink  = 0;
                lqs->lqs_last_ishrink  = 0;
        }
        lqs_initref(lqs);

        spin_lock(&qctxt->lqc_lock);
        if (!qctxt->lqc_valid)
                rc = -EBUSY;
        else
                rc = lustre_hash_add_unique(qctxt->lqc_lqs_hash,
                                    &lqs->lqs_key, &lqs->lqs_hash);
        spin_unlock(&qctxt->lqc_lock);

        if (!rc)
                lqs_getref(lqs);

 out:
        if (rc && lqs)
                OBD_FREE_PTR(lqs);

        if (rc)
                return ERR_PTR(rc);
        else
                return lqs;
}

struct lustre_qunit_size *quota_search_lqs(unsigned long long lqs_key,
                                           struct lustre_quota_ctxt *qctxt,
                                           int create)
{
        struct lustre_qunit_size *lqs;
        int rc = 0;

 search_lqs:
        lqs = lustre_hash_lookup(qctxt->lqc_lqs_hash, &lqs_key);
        if (IS_ERR(lqs))
                GOTO(out, rc = PTR_ERR(lqs));

        if (create && lqs == NULL) {
                /* if quota_create_lqs is successful, it will get a
                 * ref to the lqs. The ref will be released when
                 * qctxt_cleanup() or quota is nullified */
                lqs = quota_create_lqs(lqs_key, qctxt);
                if (IS_ERR(lqs))
                        rc = PTR_ERR(lqs);
                if (rc == -EALREADY)
                        GOTO(search_lqs, rc = 0);
                /* get a reference for the caller when creating lqs
                 * successfully */
                if (rc == 0)
                        lqs_getref(lqs);
        }

        if (lqs && rc == 0)
                LQS_DEBUG(lqs, "%s\n",
                          (create == 1 ? "create lqs" : "search lqs"));

 out:
        if (rc == 0) {
                return lqs;
        } else {
                CDEBUG(D_ERROR, "get lqs error(rc: %d)\n", rc);
                return ERR_PTR(rc);
        }
}

int quota_adjust_slave_lqs(struct quota_adjust_qunit *oqaq,
                           struct lustre_quota_ctxt *qctxt)
{
        struct lustre_qunit_size *lqs = NULL;
        unsigned long *unit, *tune;
        signed long tmp = 0;
        cfs_time_t time_limit = 0, *shrink;
        int i, rc = 0;
        ENTRY;

        LASSERT(qctxt);
        lqs = quota_search_lqs(LQS_KEY(QAQ_IS_GRP(oqaq), oqaq->qaq_id),
                               qctxt, QAQ_IS_CREATE_LQS(oqaq) ? 1 : 0);
        if (lqs == NULL || IS_ERR(lqs)){
                CDEBUG(D_ERROR, "fail to find a lqs(%s id: %u)!\n",
                       QAQ_IS_GRP(oqaq) ? "group" : "user", oqaq->qaq_id);
                RETURN(PTR_ERR(lqs));
        }

        if (OBD_FAIL_CHECK(OBD_FAIL_QUOTA_WITHOUT_CHANGE_QS)) {
                lqs->lqs_bunit_sz = qctxt->lqc_bunit_sz;
                lqs->lqs_btune_sz = qctxt->lqc_btune_sz;
                lqs->lqs_iunit_sz = qctxt->lqc_iunit_sz;
                lqs->lqs_itune_sz = qctxt->lqc_itune_sz;
                lqs_putref(lqs);
                RETURN(0);
        }

        CDEBUG(D_QUOTA, "before: bunit: %lu, iunit: %lu.\n",
               lqs->lqs_bunit_sz, lqs->lqs_iunit_sz);
        spin_lock(&lqs->lqs_lock);
        for (i = 0; i < 2; i++) {
                if (i == 0 && !QAQ_IS_ADJBLK(oqaq))
                        continue;

                if (i == 1 && !QAQ_IS_ADJINO(oqaq))
                        continue;

                tmp = i ? (lqs->lqs_iunit_sz - oqaq->qaq_iunit_sz) :
                          (lqs->lqs_bunit_sz - oqaq->qaq_bunit_sz);
                shrink = i ? &lqs->lqs_last_ishrink :
                             &lqs->lqs_last_bshrink;
                time_limit = cfs_time_add(i ? lqs->lqs_last_ishrink :
                                              lqs->lqs_last_bshrink,
                                   cfs_time_seconds(qctxt->lqc_switch_seconds));
                unit = i ? &lqs->lqs_iunit_sz : &lqs->lqs_bunit_sz;
                tune = i ? &lqs->lqs_itune_sz : &lqs->lqs_btune_sz;

                /* quota master shrinks */
                if (qctxt->lqc_handler && tmp > 0)
                        *shrink = cfs_time_current();

                /* quota master enlarges */
                if (qctxt->lqc_handler && tmp < 0) {
                        /* in case of ping-pong effect, don't enlarge lqs
                         * in a short time */
                        if (*shrink &&
                            cfs_time_before(cfs_time_current(), time_limit))
                                tmp = 0;
                }

                /* when setquota, don't enlarge lqs b=18616 */
                if (QAQ_IS_CREATE_LQS(oqaq) && tmp < 0)
                        tmp = 0;

                if (tmp != 0) {
                        *unit = i ? oqaq->qaq_iunit_sz : oqaq->qaq_bunit_sz;
                        *tune = (*unit) / 2;
                }


                if (tmp > 0)
                        rc |= i ? LQS_INO_DECREASE : LQS_BLK_DECREASE;
                if (tmp < 0)
                        rc |= i ? LQS_INO_INCREASE : LQS_BLK_INCREASE;
        }
        spin_unlock(&lqs->lqs_lock);
        CDEBUG(D_QUOTA, "after: bunit: %lu, iunit: %lu.\n",
               lqs->lqs_bunit_sz, lqs->lqs_iunit_sz);

        lqs_putref(lqs);

        RETURN(rc);
}

int filter_quota_adjust_qunit(struct obd_export *exp,
                              struct quota_adjust_qunit *oqaq,
                              struct lustre_quota_ctxt *qctxt)
{
        struct obd_device *obd = exp->exp_obd;
        unsigned int uid = 0, gid = 0;
        int rc = 0;
        ENTRY;

        LASSERT(oqaq);
        LASSERT(QAQ_IS_ADJBLK(oqaq));
        rc = quota_adjust_slave_lqs(oqaq, qctxt);
        if (rc < 0) {
                CERROR("adjust mds slave's qunit size failed!(rc:%d)\n", rc);
                RETURN(rc);
        }
        if (QAQ_IS_GRP(oqaq))
                gid = oqaq->qaq_id;
        else
                uid = oqaq->qaq_id;

        if (rc > 0) {
                rc = qctxt_adjust_qunit(obd, qctxt, uid, gid, 1, 0, NULL);
                if (rc == -EDQUOT || rc == -EBUSY ||
                    rc == QUOTA_REQ_RETURNED || rc == -EAGAIN) {
                        CDEBUG(D_QUOTA, "rc: %d.\n", rc);
                        rc = 0;
                }
                if (rc)
                        CERROR("slave adjust block quota failed!(rc:%d)\n", rc);
        }
        RETURN(rc);
}
#endif /* __KERNEL__ */
#endif

int client_quota_adjust_qunit(struct obd_export *exp,
                              struct quota_adjust_qunit *oqaq,
                              struct lustre_quota_ctxt *qctxt)
{
        struct ptlrpc_request *req;
        struct quota_adjust_qunit *oqa;
        __u32 size[2] = { sizeof(struct ptlrpc_body), sizeof(*oqaq) };
        int rc = 0;
        ENTRY;

        /* client don't support this kind of operation, abort it */
        if (!(exp->exp_connect_flags & OBD_CONNECT_CHANGE_QS)||
            OBD_FAIL_CHECK(OBD_FAIL_QUOTA_WITHOUT_CHANGE_QS)) {
                CDEBUG(D_QUOTA, "osc: %s don't support change qunit size\n",
                       exp->exp_obd->obd_name);
                RETURN(rc);
        }
        if (strcmp(exp->exp_obd->obd_type->typ_name, LUSTRE_OSC_NAME))
                RETURN(-EINVAL);

        req = ptlrpc_prep_req(class_exp2cliimp(exp), LUSTRE_OST_VERSION,
                              OST_QUOTA_ADJUST_QUNIT, 2, size, NULL);
        if (!req)
                GOTO(out, rc = -ENOMEM);

        oqa = lustre_msg_buf(req->rq_reqmsg, REQ_REC_OFF, sizeof(*oqaq));
        *oqa = *oqaq;

        ptlrpc_req_set_repsize(req, 2, size);

        rc = ptlrpc_queue_wait(req);
        if (rc) {
                CERROR("%s: %s failed: rc = %d\n", exp->exp_obd->obd_name,
                       __FUNCTION__, rc);
                GOTO(out, rc);
        }
        ptlrpc_req_finished(req);
out:
        RETURN (rc);
}

int lov_quota_adjust_qunit(struct obd_export *exp,
                           struct quota_adjust_qunit *oqaq,
                           struct lustre_quota_ctxt *qctxt)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct lov_obd *lov = &obd->u.lov;
        int i, rc = 0;
        ENTRY;

        if (!QAQ_IS_ADJBLK(oqaq)) {
                CERROR("bad qaq_flags %x for lov obd.\n", oqaq->qaq_flags);
                RETURN(-EFAULT);
        }

        for (i = 0; i < lov->desc.ld_tgt_count; i++) {
                int err;

                if (!lov->lov_tgts[i]->ltd_active) {
                        CDEBUG(D_HA, "ost %d is inactive\n", i);
                        continue;
                }

                err = obd_quota_adjust_qunit(lov->lov_tgts[i]->ltd_exp, oqaq,
                                             NULL);
                if (err) {
                        if (lov->lov_tgts[i]->ltd_active && !rc)
                                rc = err;
                        continue;
                }
        }
        RETURN(rc);
}
