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
 * version 2 along with this program; If not, see [sun.com URL with a
 * copy of GPLv2].
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
# include <linux/jbd.h>
# include <linux/ext3_fs.h>
# include <linux/quota.h>
# if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0))
#  include <linux/smp_lock.h>
#  include <linux/buffer_head.h>
#  include <linux/workqueue.h>
#  include <linux/mount.h>
# else
#  include <linux/locks.h>
# endif
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
        int is_blk;

        LASSERT(qdata && lqs);
        LASSERT_SPIN_LOCKED(&lqs->lqs_lock);
        is_blk = QDATA_IS_BLK(qdata);

        if (is_chk) {
                if (is_acq) {
                        if (is_blk)
                                lqs->lqs_blk_rec += qdata->qd_count;
                        else
                                lqs->lqs_ino_rec += qdata->qd_count;
                } else {
                        if (is_blk)
                                lqs->lqs_blk_rec -= qdata->qd_count;
                        else
                                lqs->lqs_ino_rec -= qdata->qd_count;
                }
        } else {
                if (is_acq) {
                        if (is_blk)
                                lqs->lqs_blk_rec -= qdata->qd_count;
                        else
                                lqs->lqs_ino_rec -= qdata->qd_count;
                } else {
                        if (is_blk)
                                lqs->lqs_blk_rec += qdata->qd_count;
                        else
                                lqs->lqs_ino_rec += qdata->qd_count;
                }
        }
}

void qdata_to_oqaq(struct qunit_data *qdata, struct quota_adjust_qunit *oqaq)
{
        LASSERT(qdata);
        LASSERT(oqaq);

        oqaq->qaq_flags = qdata->qd_flags;
        oqaq->qaq_id    = qdata->qd_id;
        if (QDATA_IS_ADJBLK(qdata))
                oqaq->qaq_bunit_sz = qdata->qd_qunit;
        if (QDATA_IS_ADJINO(qdata))
                oqaq->qaq_iunit_sz = qdata->qd_qunit;
}

int quota_search_lqs(struct qunit_data *qdata, struct quota_adjust_qunit *oqaq,
                     struct lustre_quota_ctxt *qctxt,
                     struct lustre_qunit_size **lqs_return)
{
        struct quota_adjust_qunit *oqaq_tmp = NULL;
        ENTRY;

        LASSERT(*lqs_return == NULL);
        LASSERT(oqaq || qdata);

        if (!oqaq) {
                OBD_ALLOC_PTR(oqaq_tmp);
                if (!oqaq_tmp)
                        RETURN(-ENOMEM);
                qdata_to_oqaq(qdata, oqaq_tmp);
        } else {
                oqaq_tmp = oqaq;
        }

        *lqs_return = lustre_hash_get_object_by_key(LQC_HASH_BODY(qctxt),
                                                    oqaq_tmp);
        if (*lqs_return)
                LQS_DEBUG((*lqs_return), "show lqs\n");

        if (!oqaq)
                OBD_FREE_PTR(oqaq_tmp);
        RETURN(0);
}

int quota_create_lqs(struct qunit_data *qdata, struct quota_adjust_qunit *oqaq,
                     struct lustre_quota_ctxt *qctxt,
                     struct lustre_qunit_size **lqs_return)
{
        int rc = 0;
        struct quota_adjust_qunit *oqaq_tmp = NULL;
        struct lustre_qunit_size *lqs = NULL;
        ENTRY;

        LASSERT(*lqs_return == NULL);
        LASSERT(oqaq || qdata);

        if (!oqaq) {
                OBD_ALLOC_PTR(oqaq_tmp);
                if (!oqaq_tmp)
                        RETURN(-ENOMEM);
                qdata_to_oqaq(qdata, oqaq_tmp);
        } else {
                oqaq_tmp = oqaq;
        }

        OBD_ALLOC_PTR(lqs);
        if (!lqs)
                GOTO(out, rc = -ENOMEM);

        spin_lock_init(&lqs->lqs_lock);
        lqs->lqs_bwrite_pending = 0;
        lqs->lqs_iwrite_pending = 0;
        lqs->lqs_ino_rec = 0;
        lqs->lqs_blk_rec = 0;
        lqs->lqs_id = oqaq_tmp->qaq_id;
        lqs->lqs_flags = QAQ_IS_GRP(oqaq_tmp);
        lqs->lqs_bunit_sz = qctxt->lqc_bunit_sz;
        lqs->lqs_iunit_sz = qctxt->lqc_iunit_sz;
        lqs->lqs_btune_sz = qctxt->lqc_btune_sz;
        lqs->lqs_itune_sz = qctxt->lqc_itune_sz;
        if (qctxt->lqc_handler) {
                lqs->lqs_last_bshrink  = 0;
                lqs->lqs_last_ishrink  = 0;
        }
        lqs_initref(lqs);
        rc = lustre_hash_additem_unique(LQC_HASH_BODY(qctxt),
                                        oqaq_tmp, &lqs->lqs_hash);
        LQS_DEBUG(lqs, "create lqs\n");
        if (!rc) {
                lqs_getref(lqs);
                *lqs_return = lqs;
        }
 out:
        if (rc && lqs)
                OBD_FREE_PTR(lqs);
        if (!oqaq)
                OBD_FREE_PTR(oqaq_tmp);
        RETURN(rc);
}

int quota_adjust_slave_lqs(struct quota_adjust_qunit *oqaq,
                           struct lustre_quota_ctxt *qctxt)
{
        struct lustre_qunit_size *lqs = NULL;
        unsigned long *lbunit, *liunit, *lbtune, *litune;
        signed long b_tmp = 0, i_tmp = 0;
        cfs_time_t time_limit = 0;
        int rc = 0;
        ENTRY;

        if (OBD_FAIL_CHECK(OBD_FAIL_QUOTA_WITHOUT_CHANGE_QS))
                RETURN(0);

        LASSERT(qctxt);
search_lqs:
        rc = quota_search_lqs(NULL, oqaq, qctxt, &lqs);

        /* deleting the lqs, because a user sets lfs quota 0 0 0 0  */
        if (!oqaq->qaq_bunit_sz && !oqaq->qaq_iunit_sz && QAQ_IS_ADJBLK(oqaq) &&
            QAQ_IS_ADJINO(oqaq)) {
                if (lqs) {
                        LQS_DEBUG(lqs, "release lqs\n");
                        /* this is for quota_search_lqs */
                        lqs_putref(lqs);
                        /* this is for deleting this lqs */
                        lqs_putref(lqs);
                }
                RETURN(rc);
        }

        if (!lqs) {
                rc = quota_create_lqs(NULL, oqaq, qctxt, &lqs);
                if (rc == -EALREADY)
                        goto search_lqs;
                if (rc < 0)
                        RETURN(rc);
        }

        lbunit = &lqs->lqs_bunit_sz;
        liunit = &lqs->lqs_iunit_sz;
        lbtune = &lqs->lqs_btune_sz;
        litune = &lqs->lqs_itune_sz;

        spin_lock(&lqs->lqs_lock);
        CDEBUG(D_QUOTA, "before: bunit: %lu, iunit: %lu.\n", *lbunit, *liunit);
        /* adjust the slave's block qunit size */
        if (QAQ_IS_ADJBLK(oqaq)) {
                cfs_duration_t sec = cfs_time_seconds(qctxt->lqc_switch_seconds);

                b_tmp = *lbunit - oqaq->qaq_bunit_sz;

                if (qctxt->lqc_handler && b_tmp > 0)
                        lqs->lqs_last_bshrink = cfs_time_current();

                if (qctxt->lqc_handler && b_tmp < 0) {
                        time_limit = cfs_time_add(lqs->lqs_last_bshrink, sec);
                        if (!lqs->lqs_last_bshrink ||
                            cfs_time_after(cfs_time_current(), time_limit)) {
                                *lbunit = oqaq->qaq_bunit_sz;
                                *lbtune = (*lbunit) / 2;
                        } else {
                                b_tmp = 0;
                        }
                } else {
                        *lbunit = oqaq->qaq_bunit_sz;
                        *lbtune = (*lbunit) / 2;
                }
        }

        /* adjust the slave's file qunit size */
        if (QAQ_IS_ADJINO(oqaq)) {
                i_tmp = *liunit - oqaq->qaq_iunit_sz;

                if (qctxt->lqc_handler && i_tmp > 0)
                        lqs->lqs_last_ishrink  = cfs_time_current();

                if (qctxt->lqc_handler && i_tmp < 0) {
                        time_limit = cfs_time_add(lqs->lqs_last_ishrink,
                                                  cfs_time_seconds(qctxt->
                                                  lqc_switch_seconds));
                        if (!lqs->lqs_last_ishrink ||
                            cfs_time_after(cfs_time_current(), time_limit)) {
                                *liunit = oqaq->qaq_iunit_sz;
                                *litune = (*liunit) / 2;
                        } else {
                                i_tmp = 0;
                        }
                } else {
                        *liunit = oqaq->qaq_iunit_sz;
                        *litune = (*liunit) / 2;
                }
        }
        CDEBUG(D_QUOTA, "after: bunit: %lu, iunit: %lu.\n", *lbunit, *liunit);
        spin_unlock(&lqs->lqs_lock);

        lqs_putref(lqs);

        if (b_tmp > 0)
                rc |= LQS_BLK_DECREASE;
        else if (b_tmp < 0)
                rc |= LQS_BLK_INCREASE;

        if (i_tmp > 0)
                rc |= LQS_INO_DECREASE;
        else if (i_tmp < 0)
                rc |= LQS_INO_INCREASE;

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
                rc = qctxt_adjust_qunit(obd, qctxt, uid, gid, 1, 0);
                if (rc == -EDQUOT || rc == -EBUSY) {
                        CDEBUG(D_QUOTA, "rc: %d.\n", rc);
                        rc = 0;
                }
                if (rc)
                        CERROR("slave adjust block quota failed!(rc:%d)\n", rc);
        }
        RETURN(rc);
}
#endif /* __KERNEL__ */

int client_quota_adjust_qunit(struct obd_export *exp,
                              struct quota_adjust_qunit *oqaq,
                              struct lustre_quota_ctxt *qctxt)
{
        struct ptlrpc_request *req;
        struct quota_adjust_qunit *oqa;
        int size[2] = { sizeof(struct ptlrpc_body), sizeof(*oqaq) };
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
