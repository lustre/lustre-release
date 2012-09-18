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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2012, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#define DEBUG_SUBSYSTEM S_LQUOTA

#ifdef __KERNEL__
# include <linux/version.h>
# include <linux/module.h>
# include <linux/init.h>
# include <linux/fs.h>
# include <linux/jbd.h>
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
#include <lustre_quota.h>
#include <lprocfs_status.h>
#include "quota_internal.h"

#ifdef __KERNEL__

static cfs_time_t last_print = 0;
static DEFINE_SPINLOCK(last_print_lock);

static int filter_quota_setup(struct obd_device *obd)
{
        int rc = 0;
        struct obd_device_target *obt = &obd->u.obt;
        ENTRY;

        cfs_init_rwsem(&obt->obt_rwsem);
        obt->obt_qfmt = LUSTRE_QUOTA_V2;
        cfs_sema_init(&obt->obt_quotachecking, 1);
        rc = qctxt_init(obd, NULL);
        if (rc)
                CERROR("initialize quota context failed! (rc:%d)\n", rc);

        RETURN(rc);
}

static int filter_quota_cleanup(struct obd_device *obd)
{
        ENTRY;
        qctxt_cleanup(&obd->u.obt.obt_qctxt, 0);
        RETURN(0);
}

static int filter_quota_setinfo(struct obd_device *obd, void *data)
{
        struct obd_export *exp = data;
        struct lustre_quota_ctxt *qctxt = &obd->u.obt.obt_qctxt;
        struct obd_import *imp = exp->exp_imp_reverse;
        ENTRY;

        LASSERT(imp != NULL);

        /* setup the quota context import */
        cfs_spin_lock(&qctxt->lqc_lock);
        if (qctxt->lqc_import != NULL) {
                cfs_spin_unlock(&qctxt->lqc_lock);
                if (qctxt->lqc_import == imp)
                        CDEBUG(D_WARNING, "%s: lqc_import(%p) of obd(%p) was "
                               "activated already.\n", obd->obd_name, imp, obd);
                else
                        CERROR("%s: lqc_import(%p:%p) of obd(%p) was "
                               "activated by others.\n", obd->obd_name,
                               qctxt->lqc_import, imp, obd);
        } else {
                qctxt->lqc_import = imp;
                /* make imp's connect flags equal relative exp's connect flags
                 * adding it to avoid the scan export list */
                imp->imp_connect_data.ocd_connect_flags |=
                                (exp->exp_connect_flags &
                                 (OBD_CONNECT_QUOTA64 | OBD_CONNECT_CHANGE_QS));
                cfs_spin_unlock(&qctxt->lqc_lock);
                CDEBUG(D_QUOTA, "%s: lqc_import(%p) of obd(%p) is reactivated "
                       "now.\n", obd->obd_name, imp, obd);

                cfs_waitq_signal(&qctxt->lqc_wait_for_qmaster);
                /* start quota slave recovery thread. (release high limits) */
                qslave_start_recovery(obd, qctxt);
        }
        RETURN(0);
}

static int filter_quota_clearinfo(struct obd_export *exp, struct obd_device *obd)
{
        struct lustre_quota_ctxt *qctxt = &obd->u.obt.obt_qctxt;
        struct obd_import *imp = exp->exp_imp_reverse;
        ENTRY;

        /* lquota may be not set up before destroying export, b=14896 */
        if (!obd->obd_set_up)
                RETURN(0);

        if (unlikely(imp == NULL))
                RETURN(0);

        /* when exp->exp_imp_reverse is destroyed, the corresponding lqc_import
         * should be invalid b=12374 */
        cfs_spin_lock(&qctxt->lqc_lock);
        if (qctxt->lqc_import == imp) {
                qctxt->lqc_import = NULL;
                cfs_spin_unlock(&qctxt->lqc_lock);
                CDEBUG(D_QUOTA, "%s: lqc_import(%p) of obd(%p) is invalid now.\n",
                       obd->obd_name, imp, obd);
                ptlrpc_cleanup_imp(imp);
                dqacq_interrupt(qctxt);
        } else {
                cfs_spin_unlock(&qctxt->lqc_lock);
        }
        RETURN(0);
}

static int filter_quota_enforce(struct obd_device *obd, unsigned int ignore)
{
        ENTRY;

        if (!ll_sb_any_quota_active(obd->u.obt.obt_sb))
                RETURN(0);

        if (ignore) {
                CDEBUG(D_QUOTA, "blocks will be written with ignoring quota.\n");
                cfs_cap_raise(CFS_CAP_SYS_RESOURCE);
        } else {
                cfs_cap_lower(CFS_CAP_SYS_RESOURCE);
        }

        RETURN(0);
}

#define GET_OA_ID(flag, oa) (flag == USRQUOTA ? oa->o_uid : oa->o_gid)
static int filter_quota_getflag(struct obd_device *obd, struct obdo *oa)
{
        struct obd_device_target *obt = &obd->u.obt;
        struct lustre_quota_ctxt *qctxt = &obt->obt_qctxt;
        int err, cnt, rc = 0;
        struct obd_quotactl *oqctl;
        ENTRY;

        if (!ll_sb_any_quota_active(obt->obt_sb))
                RETURN(0);

        OBD_ALLOC_PTR(oqctl);
        if (!oqctl)
                RETURN(-ENOMEM);

        /* set over quota flags for a uid/gid */
        oa->o_valid |= OBD_MD_FLUSRQUOTA | OBD_MD_FLGRPQUOTA;
        oa->o_flags &= ~(OBD_FL_NO_USRQUOTA | OBD_FL_NO_GRPQUOTA);

        for (cnt = 0; cnt < MAXQUOTAS; cnt++) {
                struct lustre_qunit_size *lqs = NULL;

                /* check if quota is enabled */
                if (!ll_sb_has_quota_active(obt->obt_sb, cnt))
                        continue;

                lqs = quota_search_lqs(LQS_KEY(cnt, GET_OA_ID(cnt, oa)),
                                       qctxt, 0);
                if (IS_ERR(lqs)) {
                        rc = PTR_ERR(lqs);
                        CDEBUG(D_QUOTA, "search lqs for %s %d failed, "
                               "(rc = %d)\n",
                               cnt == USRQUOTA ? "user" : "group",
                               GET_OA_ID(cnt, oa), rc);
                        break;
                } else if (lqs == NULL) {
                        /* continue to check group quota if the file's owner
                         * doesn't have quota limit. LU-530 */
                        continue;
                } else {
                        cfs_spin_lock(&lqs->lqs_lock);
                        if (lqs->lqs_bunit_sz <= qctxt->lqc_sync_blk) {
                                oa->o_flags |= (cnt == USRQUOTA) ?
                                        OBD_FL_NO_USRQUOTA : OBD_FL_NO_GRPQUOTA;
                                cfs_spin_unlock(&lqs->lqs_lock);
                                CDEBUG(D_QUOTA, "set sync flag: bunit(%lu), "
                                       "sync_blk(%d)\n", lqs->lqs_bunit_sz,
                                       qctxt->lqc_sync_blk);
                                /* this is for quota_search_lqs */
                                lqs_putref(lqs);
                                continue;
                        }
                        cfs_spin_unlock(&lqs->lqs_lock);
                        /* this is for quota_search_lqs */
                        lqs_putref(lqs);
                }

                memset(oqctl, 0, sizeof(*oqctl));

                oqctl->qc_cmd = Q_GETQUOTA;
                oqctl->qc_type = cnt;
                oqctl->qc_id = (cnt == USRQUOTA) ? oa->o_uid : oa->o_gid;
                err = fsfilt_quotactl(obd, obt->obt_sb, oqctl);
                if (err) {
                        if (!rc)
                                rc = err;
                        oa->o_valid &= ~((cnt == USRQUOTA) ? OBD_MD_FLUSRQUOTA :
                                                             OBD_MD_FLGRPQUOTA);
                        CDEBUG(D_QUOTA, "fsfilt getquota for %s %d failed, "
                               "(rc = %d)\n",
                               cnt == USRQUOTA ? "user" : "group",
                               cnt == USRQUOTA ? oa->o_uid : oa->o_gid, err);
                        continue;
                }

                if (oqctl->qc_dqblk.dqb_bhardlimit &&
                   (toqb(oqctl->qc_dqblk.dqb_curspace) >=
                    oqctl->qc_dqblk.dqb_bhardlimit)) {
                        oa->o_flags |= (cnt == USRQUOTA) ?
                                OBD_FL_NO_USRQUOTA : OBD_FL_NO_GRPQUOTA;
                        CDEBUG(D_QUOTA, "out of quota for %s %d\n",
                               cnt == USRQUOTA ? "user" : "group",
                               cnt == USRQUOTA ? oa->o_uid : oa->o_gid);
                }
        }
        OBD_FREE_PTR(oqctl);
        RETURN(rc);
}

/**
 * check whether the left quota of certain uid and gid can satisfy a block_write
 * or inode_create rpc. When need to acquire quota, return QUOTA_RET_ACQUOTA
 */
static int quota_check_common(struct obd_device *obd, const unsigned int id[],
                              int pending[], int count, int cycle, int isblk,
                              struct inode *inode, int frags)
{
        struct lustre_quota_ctxt *qctxt = &obd->u.obt.obt_qctxt;
        int i;
        struct qunit_data qdata[MAXQUOTAS];
        int mb = 0;
        int rc = 0, rc2[2] = { 0, 0 };
        ENTRY;

        cfs_spin_lock(&qctxt->lqc_lock);
        if (!qctxt->lqc_valid){
                cfs_spin_unlock(&qctxt->lqc_lock);
                RETURN(rc);
        }
        cfs_spin_unlock(&qctxt->lqc_lock);

        for (i = 0; i < MAXQUOTAS; i++) {
                struct lustre_qunit_size *lqs = NULL;

                qdata[i].qd_id = id[i];
                qdata[i].qd_flags = i;
                if (isblk)
                        QDATA_SET_BLK(&qdata[i]);
                qdata[i].qd_count = 0;

                /* check if quota is enabled */
                if (!ll_sb_has_quota_active(qctxt->lqc_sb, i))
                        continue;

                /* ignore root user */
                if (qdata[i].qd_id == 0 && !QDATA_IS_GRP(&qdata[i]))
                        continue;

                lqs = quota_search_lqs(LQS_KEY(i, id[i]), qctxt, 0);
                if (lqs == NULL || IS_ERR(lqs))
                        continue;

                if (IS_ERR(lqs)) {
                        CERROR("can not find lqs for check_common: "
                               "[id %u] [%c] [isblk %d] [count %d] [rc %ld]\n",
                               id[i], i % 2 ? 'g': 'u', isblk, count,
                               PTR_ERR(lqs));
                        RETURN(PTR_ERR(lqs));
                }

                rc2[i] = compute_remquota(obd, qctxt, &qdata[i], isblk);
                cfs_spin_lock(&lqs->lqs_lock);
                if (!cycle) {
                        if (isblk) {
                                pending[i] = count * CFS_PAGE_SIZE;
                                /* in order to complete this write, we need extra
                                 * meta blocks. This function can get it through
                                 * data needed to be written b=16542 */
                                if (inode) {
                                        mb = pending[i];
                                        rc = fsfilt_get_mblk(obd, qctxt->lqc_sb,
                                                             &mb, inode,
                                                             frags);
                                        if (rc)
                                                CERROR("%s: can't get extra "
                                                       "meta blocks\n",
                                                       obd->obd_name);
                                        else
                                                pending[i] += mb;
                                }
                                LASSERTF(pending[i] >= 0, "pending is not valid"
                                         ", count=%d, mb=%d\n", count, mb);
                                lqs->lqs_bwrite_pending += pending[i];
                        } else {
                                pending[i] = count;
                                lqs->lqs_iwrite_pending += pending[i];
                        }
                }

                /* if xx_rec < 0, that means quota are releasing,
                 * and it may return before we use quota. So if
                 * we find this situation, we assuming it has
                 * returned b=18491 */
                if (isblk && lqs->lqs_blk_rec < 0) {
                        if (qdata[i].qd_count < -lqs->lqs_blk_rec)
                                qdata[i].qd_count = 0;
                        else
                                qdata[i].qd_count += lqs->lqs_blk_rec;
                }
                if (!isblk && lqs->lqs_ino_rec < 0) {
                        if (qdata[i].qd_count < -lqs->lqs_ino_rec)
                                qdata[i].qd_count = 0;
                        else
                                qdata[i].qd_count += lqs->lqs_ino_rec;
                }

                CDEBUG(D_QUOTA, "[id %u] [%c] [isblk %d] [count %d]"
                       " [lqs pending: %lu] [qd_count: "LPU64"] [metablocks: %d]"
                       " [pending: %d]\n", id[i], i % 2 ? 'g': 'u', isblk, count,
                       isblk ? lqs->lqs_bwrite_pending : lqs->lqs_iwrite_pending,
                       qdata[i].qd_count, mb, pending[i]);
                if (rc2[i] == QUOTA_RET_OK) {
                        if (isblk && qdata[i].qd_count < lqs->lqs_bwrite_pending)
                                rc2[i] = QUOTA_RET_ACQUOTA;
                        if (!isblk && qdata[i].qd_count <
                            lqs->lqs_iwrite_pending)
                                rc2[i] = QUOTA_RET_ACQUOTA;
                }

                cfs_spin_unlock(&lqs->lqs_lock);

                if (lqs->lqs_blk_rec  < 0 &&
                    qdata[i].qd_count <
                    lqs->lqs_bwrite_pending - lqs->lqs_blk_rec - mb)
                        OBD_FAIL_TIMEOUT(OBD_FAIL_QUOTA_DELAY_REL, 5);

                /* When cycle is zero, lqs_*_pending will be changed. We will
                 * get reference of the lqs here and put reference of lqs in
                 * quota_pending_commit b=14784 */
                if (!cycle)
                        lqs_getref(lqs);

                /* this is for quota_search_lqs */
                lqs_putref(lqs);
        }

        if (rc2[0] == QUOTA_RET_ACQUOTA || rc2[1] == QUOTA_RET_ACQUOTA)
                RETURN(QUOTA_RET_ACQUOTA);
        else
                RETURN(rc);
}

int quota_is_set(struct obd_device *obd, const unsigned int id[], int flag)
{
        struct lustre_qunit_size *lqs;
        int i, q_set = 0;

        if (!ll_sb_any_quota_active(obd->u.obt.obt_qctxt.lqc_sb))
                RETURN(0);

        for (i = 0; i < MAXQUOTAS; i++) {
                /* check if quota is enabled */
                if (!ll_sb_has_quota_active(obd->u.obt.obt_qctxt.lqc_sb, i))
                        continue;
                lqs = quota_search_lqs(LQS_KEY(i, id[i]),
                                       &obd->u.obt.obt_qctxt, 0);
                if (lqs && !IS_ERR(lqs)) {
                        if (lqs->lqs_flags & flag)
                                q_set = 1;
                        lqs_putref(lqs);
                }
        }

        return q_set;
}

static int quota_chk_acq_common(struct obd_device *obd, struct obd_export *exp,
                                const unsigned int id[], int pending[],
                                int count, quota_acquire acquire,
                                struct obd_trans_info *oti, int isblk,
                                struct inode *inode, int frags)
{
        struct lustre_quota_ctxt *qctxt = &obd->u.obt.obt_qctxt;
        struct timeval work_start;
        struct timeval work_end;
        long timediff;
        struct l_wait_info lwi = { 0 };
        int rc = 0, cycle = 0, count_err = 1;
        ENTRY;

        if (!quota_is_set(obd, id, isblk ? QB_SET : QI_SET))
                RETURN(0);

        if (isblk && (exp->exp_failed || exp->exp_abort_active_req))
                /* If the client has been evicted or if it
                 * timed out and tried to reconnect already,
                 * abort the request immediately */
                RETURN(-ENOTCONN);

        CDEBUG(D_QUOTA, "check quota for %s\n", obd->obd_name);
        pending[USRQUOTA] = pending[GRPQUOTA] = 0;
        /* Unfortunately, if quota master is too busy to handle the
         * pre-dqacq in time and quota hash on ost is used up, we
         * have to wait for the completion of in flight dqacq/dqrel,
         * in order to get enough quota for write b=12588 */
        cfs_gettimeofday(&work_start);
        while ((rc = quota_check_common(obd, id, pending, count, cycle, isblk,
                                        inode, frags)) &
               QUOTA_RET_ACQUOTA) {
		struct ptlrpc_thread *thr = oti != NULL ?
					    oti->oti_thread : NULL;

		cfs_spin_lock(&qctxt->lqc_lock);
		if (!qctxt->lqc_import && oti != NULL) {
			cfs_spin_unlock(&qctxt->lqc_lock);

			LASSERT(thr != NULL);
			/* The recovery thread doesn't have watchdog
			 * attached. LU-369 */
			if (thr->t_watchdog != NULL)
				lc_watchdog_disable(thr->t_watchdog);
			CDEBUG(D_QUOTA, "sleep for quota master\n");
			l_wait_event(qctxt->lqc_wait_for_qmaster,
				     check_qm(qctxt), &lwi);

			CDEBUG(D_QUOTA, "wake up when quota master is back\n");
			if (thr->t_watchdog != NULL) {
				lc_watchdog_touch(thr->t_watchdog,
				   ptlrpc_server_get_timeout(thr->t_svcpt));
			}
                } else {
                        cfs_spin_unlock(&qctxt->lqc_lock);
                }

                cycle++;
                if (isblk)
                        OBD_FAIL_TIMEOUT(OBD_FAIL_OST_HOLD_WRITE_RPC, 90);
                /* after acquire(), we should run quota_check_common again
                 * so that we confirm there are enough quota to finish write */
                rc = acquire(obd, id, oti, isblk);

                /* please reference to dqacq_completion for the below */
                /* a new request is finished, try again */
                if (rc == QUOTA_REQ_RETURNED) {
                        CDEBUG(D_QUOTA, "finish a quota req, try again\n");
                        continue;
                }

                /* it is out of quota already */
                if (rc == -EDQUOT) {
                        CDEBUG(D_QUOTA, "out of quota,  return -EDQUOT\n");
                        break;
                }

                /* Related quota has been disabled by master, but enabled by
                 * slave, do not try again. */
                if (unlikely(rc == -ESRCH)) {
                        CERROR("mismatched quota configuration, stop try.\n");
                        break;
                }

                if (isblk && (exp->exp_failed || exp->exp_abort_active_req))
                        /* The client has been evicted or tried to
                         * to reconnect already, abort the request */
                        RETURN(-ENOTCONN);

                /* -EBUSY and others, wait a second and try again */
                if (rc < 0) {
                        cfs_waitq_t        waitq;
                        struct l_wait_info lwi;

			if (thr != NULL && thr->t_watchdog != NULL)
				lc_watchdog_touch(thr->t_watchdog,
				   ptlrpc_server_get_timeout(thr->t_svcpt));
                        CDEBUG(D_QUOTA, "rc: %d, count_err: %d\n", rc,
                               count_err++);

                        cfs_waitq_init(&waitq);
                        lwi = LWI_TIMEOUT(cfs_time_seconds(min(cycle, 10)), NULL,
                                          NULL);
                        l_wait_event(waitq, 0, &lwi);
                }

                if (rc < 0 || cycle % 10 == 0) {
                        cfs_spin_lock(&last_print_lock);
                        if (last_print == 0 ||
                            cfs_time_before((last_print + cfs_time_seconds(30)),
                                            cfs_time_current())) {
                                last_print = cfs_time_current();
                                cfs_spin_unlock(&last_print_lock);
                                CWARN("still haven't managed to acquire quota "
                                      "space from the quota master after %d "
                                      "retries (err=%d, rc=%d)\n",
                                      cycle, count_err - 1, rc);
                        } else {
                                cfs_spin_unlock(&last_print_lock);
                        }
                }

                CDEBUG(D_QUOTA, "recheck quota with rc: %d, cycle: %d\n", rc,
                       cycle);
        }
        cfs_gettimeofday(&work_end);
        timediff = cfs_timeval_sub(&work_end, &work_start, NULL);
        lprocfs_counter_add(qctxt->lqc_stats,
                            isblk ? LQUOTA_WAIT_FOR_CHK_BLK :
                                    LQUOTA_WAIT_FOR_CHK_INO,
                            timediff);

        if (rc > 0)
                rc = 0;
        RETURN(rc);
}

/**
 * when a block_write or inode_create rpc is finished, adjust the record for
 * pending blocks and inodes
 */
static int quota_pending_commit(struct obd_device *obd, const unsigned int id[],
                                int pending[], int isblk)
{
        struct lustre_quota_ctxt *qctxt = &obd->u.obt.obt_qctxt;
        struct timeval work_start;
        struct timeval work_end;
        long timediff;
        int i;
        struct qunit_data qdata[MAXQUOTAS];
        ENTRY;

        CDEBUG(D_QUOTA, "commit pending quota for  %s\n", obd->obd_name);
        CLASSERT(MAXQUOTAS < 4);
        if (!ll_sb_any_quota_active(qctxt->lqc_sb))
                RETURN(0);

        cfs_gettimeofday(&work_start);
        for (i = 0; i < MAXQUOTAS; i++) {
                struct lustre_qunit_size *lqs = NULL;

                LASSERT(pending[i] >= 0);
                if (pending[i] == 0)
                        continue;

                qdata[i].qd_id = id[i];
                qdata[i].qd_flags = i;
                if (isblk)
                        QDATA_SET_BLK(&qdata[i]);
                qdata[i].qd_count = 0;

                if (qdata[i].qd_id == 0 && !QDATA_IS_GRP(&qdata[i]))
                        continue;

                lqs = quota_search_lqs(LQS_KEY(i, qdata[i].qd_id), qctxt, 0);
                if (lqs == NULL || IS_ERR(lqs)) {
                        CERROR("can not find lqs for pending_commit: "
                               "[id %u] [%c] [pending %u] [isblk %d] (rc %ld), "
                               "maybe cause unexpected lqs refcount error!\n",
                               id[i], i ? 'g': 'u', pending[i], isblk,
                               lqs ? PTR_ERR(lqs) : -1);
                        continue;
                }

                cfs_spin_lock(&lqs->lqs_lock);
                if (isblk) {
                        LASSERTF(lqs->lqs_bwrite_pending >= pending[i],
                                 "there are too many blocks! [id %u] [%c] "
                                 "[bwrite_pending %lu] [pending %u]\n",
                                 id[i], i % 2 ? 'g' : 'u',
                                 lqs->lqs_bwrite_pending, pending[i]);

                        lqs->lqs_bwrite_pending -= pending[i];
                } else {
                        LASSERTF(lqs->lqs_iwrite_pending >= pending[i],
                                "there are too many files! [id %u] [%c] "
                                "[iwrite_pending %lu] [pending %u]\n",
                                id[i], i % 2 ? 'g' : 'u',
                                lqs->lqs_iwrite_pending, pending[i]);

                        lqs->lqs_iwrite_pending -= pending[i];
                }
                CDEBUG(D_QUOTA, "%s: lqs_pending=%lu pending[%d]=%d isblk=%d\n",
                       obd->obd_name,
                       isblk ? lqs->lqs_bwrite_pending : lqs->lqs_iwrite_pending,
                       i, pending[i], isblk);
                cfs_spin_unlock(&lqs->lqs_lock);

                /* for quota_search_lqs in pending_commit */
                lqs_putref(lqs);
                /* for quota_search_lqs in quota_check */
                lqs_putref(lqs);
        }
        cfs_gettimeofday(&work_end);
        timediff = cfs_timeval_sub(&work_end, &work_start, NULL);
        lprocfs_counter_add(qctxt->lqc_stats,
                            isblk ? LQUOTA_WAIT_FOR_COMMIT_BLK :
                                    LQUOTA_WAIT_FOR_COMMIT_INO,
                            timediff);

        RETURN(0);
}

static int mds_quota_init(void)
{
        return lustre_dquot_init();
}

static int mds_quota_exit(void)
{
        lustre_dquot_exit();
        return 0;
}

static int mds_quota_setup(struct obd_device *obd)
{
        struct obd_device_target *obt = &obd->u.obt;
        struct mds_obd *mds = &obd->u.mds;
        int rc;
        ENTRY;

        if (unlikely(mds->mds_quota)) {
                CWARN("try to reinitialize quota context!\n");
                RETURN(0);
        }

        cfs_init_rwsem(&obt->obt_rwsem);
        obt->obt_qfmt = LUSTRE_QUOTA_V2;
        mds->mds_quota_info.qi_version = LUSTRE_QUOTA_V2;
        cfs_sema_init(&obt->obt_quotachecking, 1);
        /* initialize quota master and quota context */
        cfs_init_rwsem(&mds->mds_qonoff_sem);
        rc = qctxt_init(obd, dqacq_handler);
        if (rc) {
                CERROR("%s: initialize quota context failed! (rc:%d)\n",
                       obd->obd_name, rc);
                RETURN(rc);
        }
        mds->mds_quota = 1;
        RETURN(rc);
}

static int mds_quota_cleanup(struct obd_device *obd)
{
        ENTRY;
        if (unlikely(!obd->u.mds.mds_quota))
                RETURN(0);

        qctxt_cleanup(&obd->u.obt.obt_qctxt, 0);
        RETURN(0);
}

static int mds_quota_setinfo(struct obd_device *obd, void *data)
{
        struct lustre_quota_ctxt *qctxt = &obd->u.obt.obt_qctxt;
        ENTRY;

        if (unlikely(!obd->u.mds.mds_quota))
                RETURN(0);

        if (data != NULL)
                QUOTA_MASTER_READY(qctxt);
        else
                QUOTA_MASTER_UNREADY(qctxt);
        RETURN(0);
}

static int mds_quota_fs_cleanup(struct obd_device *obd)
{
        struct mds_obd *mds = &obd->u.mds;
        struct obd_quotactl oqctl;
        ENTRY;

        if (unlikely(!mds->mds_quota))
                RETURN(0);

        mds->mds_quota = 0;
        memset(&oqctl, 0, sizeof(oqctl));
        oqctl.qc_type = UGQUOTA;

        cfs_down_write(&mds->mds_qonoff_sem);
        mds_admin_quota_off(obd, &oqctl);
        cfs_up_write(&mds->mds_qonoff_sem);
        RETURN(0);
}

static int quota_acquire_common(struct obd_device *obd, const unsigned int id[],
                                struct obd_trans_info *oti, int isblk)
{
        struct lustre_quota_ctxt *qctxt = &obd->u.obt.obt_qctxt;
        int rc;
        ENTRY;

        rc = qctxt_adjust_qunit(obd, qctxt, id, isblk, 1, oti);
        RETURN(rc);
}

quota_interface_t mds_quota_interface = {
        .quota_init     = mds_quota_init,
        .quota_exit     = mds_quota_exit,
        .quota_setup    = mds_quota_setup,
        .quota_cleanup  = mds_quota_cleanup,
        .quota_check    = target_quota_check,
        .quota_ctl      = mds_quota_ctl,
        .quota_setinfo  = mds_quota_setinfo,
        .quota_fs_cleanup = mds_quota_fs_cleanup,
        .quota_recovery = mds_quota_recovery,
        .quota_adjust   = mds_quota_adjust,
        .quota_chkquota = quota_chk_acq_common,
        .quota_acquire  = quota_acquire_common,
        .quota_pending_commit = quota_pending_commit,
};

quota_interface_t filter_quota_interface = {
        .quota_setup    = filter_quota_setup,
        .quota_cleanup  = filter_quota_cleanup,
        .quota_check    = target_quota_check,
        .quota_ctl      = filter_quota_ctl,
        .quota_setinfo  = filter_quota_setinfo,
        .quota_clearinfo = filter_quota_clearinfo,
        .quota_enforce  = filter_quota_enforce,
        .quota_getflag  = filter_quota_getflag,
        .quota_acquire  = quota_acquire_common,
        .quota_adjust   = filter_quota_adjust,
        .quota_chkquota = quota_chk_acq_common,
        .quota_adjust_qunit   = filter_quota_adjust_qunit,
        .quota_pending_commit = quota_pending_commit,
};

cfs_proc_dir_entry_t *lquota_type_proc_dir = NULL;

static int __init init_lustre_quota(void)
{
        int rc = 0;

        lquota_type_proc_dir = lprocfs_register(OBD_LQUOTA_DEVICENAME,
                                                proc_lustre_root,
                                                NULL, NULL);
        if (IS_ERR(lquota_type_proc_dir)) {
                CERROR("LProcFS failed in lquota-init\n");
                rc = PTR_ERR(lquota_type_proc_dir);
                return rc;
        }

        rc = qunit_cache_init();
        if (rc)
                return rc;

        PORTAL_SYMBOL_REGISTER(filter_quota_interface);
        PORTAL_SYMBOL_REGISTER(mds_quota_interface);

        return 0;
}

static void /*__exit*/ exit_lustre_quota(void)
{
        PORTAL_SYMBOL_UNREGISTER(filter_quota_interface);
        PORTAL_SYMBOL_UNREGISTER(mds_quota_interface);

        qunit_cache_cleanup();

        if (lquota_type_proc_dir)
                lprocfs_remove(&lquota_type_proc_dir);
}

MODULE_AUTHOR("Sun Microsystems, Inc. <http://www.lustre.org/>");
MODULE_DESCRIPTION("Lustre Quota");
MODULE_LICENSE("GPL");

cfs_module(lquota, "1.0.0", init_lustre_quota, exit_lustre_quota);

EXPORT_SYMBOL(mds_quota_interface);
EXPORT_SYMBOL(filter_quota_interface);
#endif /* __KERNEL */
