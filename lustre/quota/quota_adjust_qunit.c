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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
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
# include <linux/quota.h>
# include <linux/smp_lock.h>
# include <linux/buffer_head.h>
# include <linux/workqueue.h>
# include <linux/mount.h>
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
#include "quota_internal.h"

#ifdef HAVE_QUOTA_SUPPORT

#ifdef __KERNEL__
/**
 * This function is charge of recording lqs_ino_rec and
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

struct lustre_qunit_size *quota_search_lqs(unsigned long long lqs_key,
                                           struct lustre_quota_ctxt *qctxt,
                                           int create)
{
        struct lustre_qunit_size *lqs;
        struct lustre_qunit_size *lqs2;
        cfs_hash_t *hs = NULL;
        int rc = 0;

        cfs_spin_lock(&qctxt->lqc_lock);
        if (qctxt->lqc_valid) {
                LASSERT(qctxt->lqc_lqs_hash != NULL);
                hs = cfs_hash_getref(qctxt->lqc_lqs_hash);
        }
        cfs_spin_unlock(&qctxt->lqc_lock);

        if (hs == NULL) {
                rc = -EBUSY;
                goto out;
        }

        /* cfs_hash_lookup will +1 refcount for caller */
        lqs = cfs_hash_lookup(qctxt->lqc_lqs_hash, &lqs_key);
        if (lqs != NULL) /* found */
                goto out_put;

        if (!create)
                goto out_put;

        OBD_ALLOC_PTR(lqs);
        if (!lqs) {
                rc = -ENOMEM;
                goto out_put;
        }

        lqs->lqs_key = lqs_key;

        cfs_spin_lock_init(&lqs->lqs_lock);

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
        if (qctxt->lqc_handler) {
                lqs->lqs_last_bshrink  = 0;
                lqs->lqs_last_ishrink  = 0;
        }

        lqs->lqs_ctxt = qctxt; /* must be called before lqs_initref */
        cfs_atomic_set(&lqs->lqs_refcount, 1); /* 1 for caller */
        cfs_atomic_inc(&lqs->lqs_ctxt->lqc_lqs);

        /* lqc_lqs_hash will take +1 refcount on lqs on adding */
        lqs2 = cfs_hash_findadd_unique(qctxt->lqc_lqs_hash,
                                       &lqs->lqs_key, &lqs->lqs_hash);
        if (lqs2 == lqs) /* added to hash */
                goto out_put;

        create = 0;
        lqs_putref(lqs);
        lqs = lqs2;

 out_put:
        cfs_hash_putref(hs);
 out:
        if (rc != 0) { /* error */
                CERROR("get lqs error(rc: %d)\n", rc);
                return ERR_PTR(rc);
        }

        if (lqs != NULL) {
                LQS_DEBUG(lqs, "%s\n",
                          (create == 1 ? "create lqs" : "search lqs"));
        }
        return lqs;
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
                CERROR("fail to find a lqs for %sid %u!\n",
                       QAQ_IS_GRP(oqaq) ? "g" : "u", oqaq->qaq_id);
                RETURN(PTR_ERR(lqs));
        }

        CDEBUG(D_QUOTA, "before: bunit: %lu, iunit: %lu.\n",
               lqs->lqs_bunit_sz, lqs->lqs_iunit_sz);
        cfs_spin_lock(&lqs->lqs_lock);
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
        cfs_spin_unlock(&lqs->lqs_lock);
        CDEBUG(D_QUOTA, "after: bunit: %lu, iunit: %lu.\n",
               lqs->lqs_bunit_sz, lqs->lqs_iunit_sz);

        lqs_putref(lqs);

        RETURN(rc);
}

int filter_quota_adjust_qunit(struct obd_export *exp,
                              struct quota_adjust_qunit *oqaq,
                              struct lustre_quota_ctxt *qctxt,
                              struct ptlrpc_request_set *rqset)
{
        struct obd_device *obd = exp->exp_obd;
        unsigned int id[MAXQUOTAS] = { 0, 0 };
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
                id[GRPQUOTA] = oqaq->qaq_id;
        else
                id[USRQUOTA] = oqaq->qaq_id;

        if (rc > 0) {
                rc = qctxt_adjust_qunit(obd, qctxt, id, 1, 0, NULL);
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
